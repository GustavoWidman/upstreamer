//! The engine against hand-built client frames (RFC 9113 layouts, RFC 7541 literals), and
//! the driver's allocation count against a real client.

use super::engine::{
    BUDGET_BURST, BUDGET_PER_SECOND, Begin, CONNECTION_WINDOW, MAX_HEADER_LIST, OUT_HIGH,
    STREAM_WINDOW,
};
use super::frame::{self, Reason};
use super::harness::{self, Happened, Responder, Session};
use super::hpack::Decoder;
use crate::msg::{Fields, Method, RequestHead, Status};
use bytes::Bytes;

const GET: [(&str, &str); 4] = [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/"),
];
const POST: [(&str, &str); 4] = [
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/upload"),
];

/// A request's fields.
type Request = Vec<(&'static str, &'static str)>;

/// What the server wrote, frame by frame.
#[derive(Debug, PartialEq)]
enum Sent {
    Headers {
        stream: u32,
        fields: Vec<(String, String)>,
        end: bool,
    },
    Data {
        stream: u32,
        len: usize,
        end: bool,
    },
    Reset {
        stream: u32,
        code: u32,
    },
    GoAway {
        last: u32,
        code: u32,
    },
    Window {
        stream: u32,
        by: u32,
    },
    Ping {
        ack: bool,
        opaque: Vec<u8>,
    },
    Settings {
        ack: bool,
        values: Vec<(u16, u32)>,
    },
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    frame::put_head(&mut out, payload.len(), kind, flags, stream);
    out.extend_from_slice(payload);
    out
}

/// An HPACK integer with a 7-bit prefix (RFC 7541 5.1).
fn length(out: &mut Vec<u8>, mut n: usize) {
    if n < 127 {
        return out.push(n as u8);
    }
    out.push(127);
    n -= 127;
    while n >= 128 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// A field block of literals without indexing and with raw strings (RFC 7541 6.2.2).
fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        out.push(0);
        length(&mut out, name.len());
        out.extend_from_slice(name.as_bytes());
        length(&mut out, value.len());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn headers(stream: u32, fields: &[(&str, &str)], end_stream: bool) -> Vec<u8> {
    let flags = frame::END_HEADERS | if end_stream { frame::END_STREAM } else { 0 };
    frame(frame::HEADERS, flags, stream, &block(fields))
}

fn data(stream: u32, len: usize, end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { frame::END_STREAM } else { 0 };
    frame(frame::DATA, flags, stream, &vec![b'd'; len])
}

fn rst_stream(stream: u32) -> Vec<u8> {
    frame(frame::RST_STREAM, 0, stream, &8u32.to_be_bytes())
}

fn window_update(stream: u32, by: u32) -> Vec<u8> {
    frame(frame::WINDOW_UPDATE, 0, stream, &by.to_be_bytes())
}

fn settings(values: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    frame::put_settings(&mut out, values);
    out
}

fn ping() -> Vec<u8> {
    frame(frame::PING, 0, 0, b"01234567")
}

fn requests(happened: &[Happened]) -> usize {
    happened
        .iter()
        .filter(|h| matches!(h, Happened::Request { .. }))
        .count()
}

fn cancelled(happened: &[Happened]) -> Vec<u32> {
    happened
        .iter()
        .filter_map(|h| match h {
            Happened::Cancel { slot } => Some(*slot),
            Happened::Request { .. } => None,
        })
        .collect()
}

struct Client {
    session: Session,
    decoder: Decoder,
}

impl Client {
    /// A connection past both prefaces.
    fn new() -> Client {
        Client::with(128, 100)
    }

    fn with(max_streams: u32, max_fields: u16) -> Client {
        let mut client = Client {
            session: Session::new(max_streams, max_fields),
            decoder: Decoder::new(),
        };
        let mut hello = frame::PREFACE.to_vec();
        hello.extend_from_slice(&settings(&[]));
        client.feed(&hello).unwrap();
        client.sent();
        client
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Happened>, Reason> {
        self.session.feed(bytes)
    }

    /// Feeds bytes that have to be handled without a connection error.
    fn ok(&mut self, bytes: &[u8]) -> Vec<Happened> {
        self.feed(bytes).expect("no connection error")
    }

    /// Feeds a request and returns the slot it runs in, how it starts, and its head.
    fn open(
        &mut self,
        stream: u32,
        fields: &[(&str, &str)],
        end_stream: bool,
    ) -> (u32, Begin, Box<RequestHead>) {
        let mut happened = self.ok(&headers(stream, fields, end_stream));
        assert_eq!(happened.len(), 1, "one request");
        match happened.remove(0) {
            Happened::Request { slot, begin, head } => (slot, begin, head),
            Happened::Cancel { slot } => panic!("slot {slot} was cancelled"),
        }
    }

    fn get(&mut self, stream: u32) -> u32 {
        self.open(stream, &GET, true).0
    }

    /// The slots marked ready since the last look.
    fn ready(&mut self) -> Vec<u32> {
        let mut slots = Vec::new();
        self.session.ready.take(|slot| slots.push(slot));
        slots
    }

    /// What the server has written since the last look.
    fn sent(&mut self) -> Vec<Sent> {
        let written = self.session.written();
        let mut sent = Vec::new();
        let mut block: Option<(u32, bool, Vec<u8>)> = None;
        for (head, payload) in harness::frames(&written) {
            let u32_at = |at: usize| frame::u32_at(&payload[at..]);
            match head.kind {
                frame::HEADERS => {
                    assert!(block.is_none());
                    block = Some((head.stream, head.has(frame::END_STREAM), payload.clone()));
                }
                frame::CONTINUATION => {
                    let (stream, _, bytes) = block.as_mut().expect("a block to continue");
                    assert_eq!(*stream, head.stream);
                    bytes.extend_from_slice(&payload);
                }
                frame::DATA => sent.push(Sent::Data {
                    stream: head.stream,
                    len: payload.len(),
                    end: head.has(frame::END_STREAM),
                }),
                frame::RST_STREAM => sent.push(Sent::Reset {
                    stream: head.stream,
                    code: u32_at(0),
                }),
                frame::GOAWAY => sent.push(Sent::GoAway {
                    last: u32_at(0),
                    code: u32_at(4),
                }),
                frame::WINDOW_UPDATE => sent.push(Sent::Window {
                    stream: head.stream,
                    by: u32_at(0),
                }),
                frame::PING => sent.push(Sent::Ping {
                    ack: head.has(frame::ACK),
                    opaque: payload.clone(),
                }),
                frame::SETTINGS => sent.push(Sent::Settings {
                    ack: head.has(frame::ACK),
                    values: payload
                        .chunks(6)
                        .map(|s| (u16::from_be_bytes([s[0], s[1]]), frame::u32_at(&s[2..])))
                        .collect(),
                }),
                kind => panic!("the server sent a frame of type {kind}"),
            }
            if matches!(head.kind, frame::HEADERS | frame::CONTINUATION)
                && head.has(frame::END_HEADERS)
            {
                let (stream, end, bytes) = block.take().unwrap();
                let mut fields = Vec::new();
                self.decoder
                    .decode(&bytes, |name, value| {
                        fields.push((
                            String::from_utf8(name.to_vec()).unwrap(),
                            String::from_utf8(value.to_vec()).unwrap(),
                        ));
                    })
                    .expect("the server's block decodes");
                sent.push(Sent::Headers {
                    stream,
                    fields,
                    end,
                });
            }
        }
        assert!(block.is_none(), "a block left open");
        sent
    }

    /// Answers the request in `slot` with a head that promises `length` bytes.
    fn respond(&mut self, slot: u32, length: u64) {
        let engine = &mut self.session.engine;
        engine.send_head(
            slot,
            Status::OK,
            &Fields::default(),
            Some(length),
            None,
            length == 0,
        );
    }
}

fn pairs(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

fn reset(stream: u32, reason: Reason) -> Sent {
    Sent::Reset {
        stream,
        code: reason as u32,
    }
}

#[test]
fn the_server_speaks_first_and_acknowledges_the_clients_settings() {
    let mut client = Client {
        session: Session::new(128, 100),
        decoder: Decoder::new(),
    };
    assert_eq!(
        client.sent(),
        [
            Sent::Settings {
                ack: false,
                values: vec![(3, 128), (4, 1 << 20), (6, 65_536), (9, 1)],
            },
            Sent::Window {
                stream: 0,
                by: (4 << 20) - 65_535,
            },
        ]
    );
    assert!(client.session.engine.starting());
    client.ok(&frame::PREFACE[..10]);
    client.ok(&frame::PREFACE[10..]);
    client.ok(&settings(&[(1, 4096), (3, 100)]));
    assert!(!client.session.engine.starting());
    assert_eq!(
        client.sent(),
        [Sent::Settings {
            ack: true,
            values: vec![],
        }]
    );
    client.ok(&frame(frame::SETTINGS, frame::ACK, 0, b""));
    assert!(client.sent().is_empty());
}

#[test]
fn a_request_is_decoded_into_a_head_and_answered_in_frames() {
    let mut client = Client::new();
    let (slot, begin, head) = client.open(
        1,
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "Example.com:8443"),
            (":path", "/a/../b%20c?x=1"),
            ("cookie", "a=1"),
            ("accept", "*/*"),
            ("cookie", "b=2"),
        ],
        true,
    );
    assert_eq!(
        begin,
        Begin {
            preset: None,
            length: None,
            end_stream: true,
        }
    );
    assert_eq!(head.method, Method::Get);
    assert_eq!(head.path().as_bytes(), b"/b c");
    assert_eq!(head.query(), Some(&b"x=1"[..]));
    assert_eq!(head.raw_target(), b"/a/../b%20c?x=1");
    assert_eq!(head.host(), b"example.com");
    let fields: Vec<_> = head
        .fields
        .live()
        .map(|(n, v, _)| (n.to_vec(), v.to_vec()))
        .collect();
    assert_eq!(
        fields,
        [
            (b"accept".to_vec(), b"*/*".to_vec()),
            (b"cookie".to_vec(), b"a=1; b=2".to_vec()),
            (b"host".to_vec(), b"Example.com:8443".to_vec()),
        ],
        "cookie crumbs are joined and Host comes from :authority"
    );

    let mut fields = Fields::default();
    fields.push(b"content-type", b"text/plain");
    fields.push(b"connection", b"close");
    fields.push(b"keep-alive", b"timeout=5");
    fields.push(b"content-length", b"999");
    fields.push(b"date", b"the origin's");
    fields.push(b"set-cookie", b"s=1");
    let engine = &mut client.session.engine;
    let date = b"Sun, 06 Nov 1994 08:49:37 GMT";
    engine.send_head(slot, Status::OK, &fields, Some(5), Some(date), false);
    let mut body = Bytes::from_static(b"hello");
    assert!(engine.send_data(slot, &mut body, true));
    engine.finish(slot);
    assert_eq!(engine.streams(), 0);
    assert_eq!(
        client.sent(),
        [
            Sent::Headers {
                stream: 1,
                fields: pairs(&[
                    (":status", "200"),
                    ("content-type", "text/plain"),
                    ("set-cookie", "s=1"),
                    ("content-length", "5"),
                    ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ]),
                end: false,
            },
            Sent::Data {
                stream: 1,
                len: 5,
                end: true,
            },
        ],
        "framing fields come from the body, hop-by-hop fields stay behind"
    );
}

#[test]
fn an_upstreams_date_is_kept_when_none_replaces_it() {
    let mut client = Client::new();
    let slot = client.get(1);
    let mut fields = Fields::default();
    fields.push(b"date", b"the origin's");
    let engine = &mut client.session.engine;
    engine.send_head(slot, Status::NOT_FOUND, &fields, None, None, true);
    engine.finish(slot);
    assert_eq!(
        client.sent(),
        [Sent::Headers {
            stream: 1,
            fields: pairs(&[(":status", "404"), ("date", "the origin's")]),
            end: true,
        }]
    );
}

#[test]
fn malformed_requests_are_reset_and_the_connection_goes_on() {
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut fields = GET.to_vec();
        fields.extend_from_slice(extra);
        fields
    };
    let without = |name: &str| {
        GET.iter()
            .copied()
            .filter(|(n, _)| *n != name)
            .collect::<Vec<_>>()
    };
    let cases: Vec<(&str, Request, bool)> = vec![
        ("an uppercase name", with(&[("Accept", "*/*")]), true),
        ("connection", with(&[("connection", "close")]), true),
        ("keep-alive", with(&[("keep-alive", "1")]), true),
        ("proxy-connection", with(&[("proxy-connection", "x")]), true),
        (
            "transfer-encoding",
            with(&[("transfer-encoding", "chunked")]),
            true,
        ),
        ("upgrade", with(&[("upgrade", "websocket")]), true),
        ("te other than trailers", with(&[("te", "gzip")]), true),
        (
            "a pseudo-header after a field",
            vec![GET[0], GET[1], ("accept", "*/*"), GET[2], GET[3]],
            true,
        ),
        (
            "a pseudo-header twice",
            vec![GET[0], GET[0], GET[1], GET[2], GET[3]],
            true,
        ),
        (
            "an unknown pseudo-header",
            vec![GET[0], GET[1], GET[2], GET[3], (":foo", "x")],
            true,
        ),
        (
            "a response pseudo-header",
            vec![GET[0], GET[1], GET[2], GET[3], (":status", "200")],
            true,
        ),
        ("no :method", without(":method"), true),
        ("no :scheme", without(":scheme"), true),
        ("no :path", without(":path"), true),
        (
            "an empty :path",
            vec![GET[0], GET[1], GET[2], (":path", "")],
            true,
        ),
        (
            "a length that is no number",
            with(&[("content-length", "1x")]),
            false,
        ),
        ("an empty length", with(&[("content-length", "")]), false),
        (
            "two lengths",
            with(&[("content-length", "1"), ("content-length", "2")]),
            false,
        ),
        (
            "a length without a body",
            with(&[("content-length", "5")]),
            true,
        ),
        (
            "a line break in a value",
            with(&[("x-a", "a\r\nb: c")]),
            true,
        ),
        ("a NUL in a value", with(&[("x-a", "a\0b")]), true),
        ("an empty name", with(&[("", "x")]), true),
        ("a space in a name", with(&[("a b", "x")]), true),
        (
            "a method that is no token",
            vec![(":method", "GET /admin"), GET[1], GET[2], GET[3]],
            true,
        ),
        (
            "an empty method",
            vec![(":method", ""), GET[1], GET[2], GET[3]],
            true,
        ),
    ];
    let mut client = Client::new();
    let mut stream = 1;
    for (what, fields, end_stream) in cases {
        let happened = client.ok(&headers(stream, &fields, end_stream));
        assert!(happened.is_empty(), "{what}");
        assert_eq!(client.sent(), [reset(stream, Reason::Protocol)], "{what}");
        stream += 2;
    }
    assert_eq!(client.session.engine.streams(), 0);
    let (_, _, head) = client.open(stream, &with(&[("te", "trailers")]), true);
    assert_eq!(head.path().as_bytes(), b"/");
}

#[test]
fn requests_that_cannot_be_routed_start_with_their_status() {
    let authority_and = |host: &'static str| {
        let mut fields = GET.to_vec();
        fields.push(("host", host));
        fields
    };
    let path = |path: &'static str| vec![GET[0], GET[1], GET[2], (":path", path)];
    let cases: Vec<(&str, Request, Option<Status>)> = vec![
        (
            "Host names the authority",
            authority_and("EXAMPLE.com"),
            None,
        ),
        (
            "Host names another authority",
            authority_and("other.example"),
            Some(Status::BAD_REQUEST),
        ),
        (
            "neither authority nor Host",
            vec![GET[0], GET[1], GET[3]],
            Some(Status::BAD_REQUEST),
        ),
        (
            "Host alone",
            vec![GET[0], GET[1], GET[3], ("host", "example.com")],
            None,
        ),
        (
            "a path above the root",
            path("/../x"),
            Some(Status::BAD_REQUEST),
        ),
        (
            "a path with a space",
            path("/a b"),
            Some(Status::BAD_REQUEST),
        ),
        (
            "a path with a tab",
            path("/a\tb"),
            Some(Status::BAD_REQUEST),
        ),
        (
            "a path with a raw non-ASCII byte",
            path("/caf\u{e9}"),
            Some(Status::BAD_REQUEST),
        ),
        ("an escaped path", path("/caf%C3%A9?q=%20"), None),
        (
            "an authority with a space",
            vec![GET[0], GET[1], (":authority", "a b"), GET[3]],
            Some(Status::BAD_REQUEST),
        ),
        (
            "an authority with userinfo",
            vec![GET[0], GET[1], (":authority", "u@example.com"), GET[3]],
            Some(Status::BAD_REQUEST),
        ),
        (
            "a Host that is no authority",
            vec![GET[0], GET[1], GET[3], ("host", "example.com/x")],
            Some(Status::BAD_REQUEST),
        ),
        (
            "two Hosts",
            vec![
                GET[0],
                GET[1],
                GET[2],
                GET[3],
                ("host", "example.com"),
                ("host", "example.com"),
            ],
            Some(Status::BAD_REQUEST),
        ),
        (
            "a path that is a URL",
            path("http://x/"),
            Some(Status::BAD_REQUEST),
        ),
        ("the asterisk", path("*"), None),
        (
            "CONNECT",
            vec![(":method", "CONNECT"), (":authority", "example.com:443")],
            Some(Status::BAD_REQUEST),
        ),
    ];
    let mut client = Client::new();
    let mut stream = 1;
    for (what, fields, preset) in cases {
        let (slot, begin, head) = client.open(stream, &fields, true);
        assert_eq!(begin.preset, preset, "{what}");
        if preset.is_none() {
            assert_eq!(head.host(), b"example.com", "{what}");
        }
        client.session.engine.finish(slot);
        stream += 2;
    }

    let mut few = Client::with(128, 3);
    let mut fields = GET.to_vec();
    fields.extend_from_slice(&[("a", "1"), ("b", "2"), ("cookie", "c=3")]);
    assert_eq!(few.open(1, &fields, true).1.preset, None);
    fields.push(("d", "4"));
    assert_eq!(
        few.open(3, &fields, true).1.preset,
        Some(Status::HEADER_FIELDS_TOO_LARGE)
    );
}

#[test]
fn a_block_that_expands_past_the_field_limit_is_answered_431_and_not_stored() {
    let mut client = Client::new();
    let mut bomb = block(&GET);
    // A literal that enters the dynamic table (RFC 7541 6.2.1), then 2000 references to it
    // (index 62): 6 KiB on the wire, 8 MiB decoded.
    bomb.push(0x40);
    length(&mut bomb, 5);
    bomb.extend_from_slice(b"x-big");
    length(&mut bomb, 4000);
    bomb.extend_from_slice(&[b'v'; 4000]);
    bomb.extend_from_slice(&[0xbe; 2000]);
    let flags = frame::END_HEADERS | frame::END_STREAM;
    let mut happened = client.ok(&frame(frame::HEADERS, flags, 1, &bomb));
    let Some(Happened::Request { begin, head, .. }) = happened.pop() else {
        panic!("a request that is answered");
    };
    assert_eq!(begin.preset, Some(Status::HEADER_FIELDS_TOO_LARGE));
    assert!(
        head.fields.buf.len() <= MAX_HEADER_LIST + 4096,
        "{} bytes stored",
        head.fields.buf.len()
    );

    // The table took the entry all the same: the next block may refer to it.
    let mut next = block(&GET);
    next.push(0xbe);
    let mut happened = client.ok(&frame(frame::HEADERS, flags, 3, &next));
    let Some(Happened::Request { begin, head, .. }) = happened.pop() else {
        panic!("a request");
    };
    assert_eq!(begin.preset, None);
    let big = head.fields.live().find(|(name, _, _)| *name == b"x-big");
    assert_eq!(big.map(|(_, value, _)| value.len()), Some(4000));
}

#[test]
fn response_data_waits_for_the_clients_windows() {
    let mut client = Client::new();
    let slot = client.get(1);
    client.respond(slot, 100_000);
    let mut body = Bytes::from(vec![7u8; 100_000]);
    assert!(!client.session.engine.send_data(slot, &mut body, true));
    // Both windows start at 65,535 (RFC 9113 6.9.2), and no frame exceeds 16,384.
    let lens: Vec<_> = client.sent()[1..]
        .iter()
        .map(|sent| match sent {
            Sent::Data {
                len, end: false, ..
            } => *len,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(lens, [16_384, 16_384, 16_384, 16_383]);
    assert_eq!(client.session.engine.stalled_since(), Some(0));

    // Window for the stream alone is not enough.
    client.ok(&window_update(1, 100_000));
    assert_eq!(client.ready(), [slot]);
    assert!(!client.session.engine.send_data(slot, &mut body, true));
    assert!(client.sent().is_empty());

    client.ok(&window_update(0, 20_000));
    assert_eq!(client.ready(), [slot], "the connection's window wakes it");
    assert!(!client.session.engine.send_data(slot, &mut body, true));
    let data = |len, end| Sent::Data {
        stream: 1,
        len,
        end,
    };
    assert_eq!(client.sent(), [data(16_384, false), data(3_616, false)]);

    client.ok(&window_update(0, 1 << 20));
    assert_eq!(client.ready(), [slot]);
    assert!(client.session.engine.send_data(slot, &mut body, true));
    assert_eq!(client.sent(), [data(14_465, true)]);
    assert_eq!(client.session.engine.stalled_since(), None);
}

#[test]
fn a_new_initial_window_moves_the_window_of_open_streams() {
    let mut client = Client::new();
    let slot = client.get(1);
    client.respond(slot, 70_000);
    let mut body = Bytes::from(vec![7u8; 70_000]);
    assert!(!client.session.engine.send_data(slot, &mut body, true));
    client.ok(&window_update(0, 1 << 20));
    client.sent();
    client.ready();

    // 65,535 are used: a window of 0 leaves the stream 65,535 in debt (RFC 9113 6.9.2).
    client.ok(&settings(&[(4, 0)]));
    assert!(client.ready().is_empty());
    client.ok(&settings(&[(4, 70_000)]));
    assert_eq!(client.ready(), [slot]);
    assert!(client.session.engine.send_data(slot, &mut body, true));
    let sent = client.sent();
    assert_eq!(
        sent.last(),
        Some(&Sent::Data {
            stream: 1,
            len: 4_465,
            end: true,
        })
    );

    let mut client = Client::new();
    client.get(1);
    client.ok(&window_update(1, 1_000));
    assert_eq!(
        client.feed(&settings(&[(4, (1 << 31) - 1)])).err(),
        Some(Reason::FlowControl),
        "a stream's window past 2^31-1"
    );
    assert_eq!(
        Client::new().feed(&settings(&[(4, 1 << 31)])).err(),
        Some(Reason::FlowControl)
    );
}

#[test]
fn reading_a_request_body_gives_the_windows_back() {
    let mut client = Client::new();
    let (slot, begin, _) = client.open(1, &POST, false);
    assert!(!begin.end_stream);
    let mut read = 0;
    let mut updates = Vec::new();
    // 2.24 MB through a 1 MiB stream window and a 4 MiB connection window.
    for _ in 0..140 {
        client.ok(&data(1, 16_000, false));
        assert_eq!(client.ready(), [slot]);
        while let std::task::Poll::Ready(piece) = client.session.engine.read(slot) {
            read += piece.expect("the body goes on").len();
        }
        updates.extend(client.sent());
    }
    assert_eq!(read, 140 * 16_000);
    let window = |stream, frames: u32| Sent::Window {
        stream,
        by: frames * 16_000,
    };
    // Half a window at a time: 33 frames pass 512 KiB, 132 pass 2 MiB.
    assert_eq!(
        updates,
        [
            window(1, 33),
            window(1, 33),
            window(1, 33),
            window(1, 33),
            window(0, 132)
        ]
    );
    client.ok(&data(1, 0, true));
    assert_eq!(client.ready(), [slot]);
    assert_eq!(
        client.session.engine.read(slot),
        std::task::Poll::Ready(None)
    );
}

#[test]
fn data_past_a_window_is_a_flow_control_error() {
    let mut client = Client::new();
    let (slot, _, _) = client.open(1, &POST, false);
    for _ in 0..STREAM_WINDOW / 16_384 {
        client.ok(&data(1, 16_384, false));
    }
    assert_eq!(cancelled(&client.ok(&data(1, 1, false))), [slot]);
    assert_eq!(client.sent(), [reset(1, Reason::FlowControl)]);

    // The connection's window fills with the unread bodies of open streams. What the
    // reset stream had used comes back with the next update, due at half the window.
    let mut stream = 3;
    let mut received = 0;
    let failed = loop {
        client.open(stream, &POST, false);
        let mut failed = None;
        for _ in 0..STREAM_WINDOW / 16_384 {
            if let Err(reason) = client.feed(&data(stream, 16_384, false)) {
                failed = Some(reason);
                break;
            }
            received += 16_384;
        }
        if failed.is_some() {
            break failed;
        }
        stream += 2;
    };
    assert_eq!(failed, Some(Reason::FlowControl));
    let left = CONNECTION_WINDOW - (STREAM_WINDOW + 1);
    assert_eq!(received, left - left % 16_384);
}

#[test]
fn data_has_to_add_up_to_the_declared_length() {
    let mut post = POST.to_vec();
    post.push(("content-length", "10"));
    let mut client = Client::new();

    let (slot, begin, _) = client.open(1, &post, false);
    assert_eq!(begin.length, Some(10));
    assert_eq!(
        cancelled(&client.ok(&data(1, 11, false))),
        [slot],
        "too much"
    );
    assert_eq!(client.sent(), [reset(1, Reason::Protocol)]);

    let (slot, ..) = client.open(3, &post, false);
    assert_eq!(
        cancelled(&client.ok(&data(3, 5, true))),
        [slot],
        "too little"
    );
    assert_eq!(client.sent(), [reset(3, Reason::Protocol)]);

    let (slot, ..) = client.open(5, &post, false);
    client.ok(&data(5, 4, false));
    assert!(client.ok(&data(5, 6, true)).is_empty());
    let engine = &mut client.session.engine;
    let mut read = 0;
    while let std::task::Poll::Ready(Some(piece)) = engine.read(slot) {
        read += piece.len();
    }
    assert_eq!(read, 10);
    assert_eq!(engine.read(slot), std::task::Poll::Ready(None));
}

#[test]
fn padding_counts_against_the_windows_and_is_not_data() {
    let mut client = Client::new();
    let (slot, ..) = client.open(1, &POST, false);
    // Pad length 3, "ab", three octets of padding (RFC 9113 6.1).
    let padded = frame(
        frame::DATA,
        frame::PADDED | frame::END_STREAM,
        1,
        b"\x03ab\0\0\0",
    );
    client.ok(&padded);
    let engine = &mut client.session.engine;
    assert_eq!(
        engine.read(slot),
        std::task::Poll::Ready(Some(Bytes::from_static(b"ab")))
    );
    assert_eq!(engine.read(slot), std::task::Poll::Ready(None));
}

#[test]
fn a_body_in_small_frames_is_queued_as_its_bytes_in_order() {
    let mut client = Client::new();
    let (slot, ..) = client.open(1, &POST, false);
    let mut sent = Vec::new();
    let mut push = |client: &mut Client, byte: u8, len: usize| {
        let payload = vec![byte; len];
        sent.extend_from_slice(&payload);
        client.ok(&frame(frame::DATA, 0, 1, &payload));
    };
    for i in 0..1000 {
        push(&mut client, i as u8, 10);
    }
    // A payload large enough to be queued as it was read, between small ones.
    push(&mut client, b'L', 9000);
    push(&mut client, b's', 3);
    client.ok(&data(1, 0, true));

    let engine = &mut client.session.engine;
    let mut pieces = Vec::new();
    while let std::task::Poll::Ready(Some(piece)) = engine.read(slot) {
        pieces.push(piece);
    }
    let lens: Vec<_> = pieces.iter().map(Bytes::len).collect();
    assert_eq!(lens, [10_000, 9000, 3], "a thousand frames are one piece");
    assert_eq!(pieces.concat(), sent);
}

#[test]
fn trailers_end_a_request_body() {
    let mut client = Client::new();
    let (slot, ..) = client.open(1, &POST, false);
    client.ok(&data(1, 3, false));
    assert!(
        client
            .ok(&headers(1, &[("checksum", "abc")], true))
            .is_empty()
    );
    let engine = &mut client.session.engine;
    assert!(matches!(engine.read(slot), std::task::Poll::Ready(Some(_))));
    assert_eq!(engine.read(slot), std::task::Poll::Ready(None));

    let (slot, ..) = client.open(3, &POST, false);
    let happened = client.ok(&headers(3, &[("checksum", "abc")], false));
    assert_eq!(
        cancelled(&happened),
        [slot],
        "trailers that do not end the stream"
    );
    assert_eq!(client.sent(), [reset(3, Reason::Protocol)]);

    let bad = [(":path", "/"), ("Checksum", "abc"), ("x", "a\nb")];
    for (stream, bad) in [5, 7, 9].into_iter().zip(bad) {
        let (slot, ..) = client.open(stream, &POST, false);
        let happened = client.ok(&headers(stream, &[bad], true));
        assert_eq!(cancelled(&happened), [slot], "{bad:?}");
        assert_eq!(client.sent(), [reset(stream, Reason::Protocol)], "{bad:?}");
    }
}

#[test]
fn trailers_that_expand_past_the_field_limit_are_a_stream_error() {
    let mut client = Client::new();
    // A table entry with a 4000-byte name, then trailers that refer to it 4000 times.
    let mut first = block(&POST);
    first.push(0x40);
    length(&mut first, 4000);
    first.extend_from_slice(&[b'n'; 4000]);
    first.push(0);
    let happened = client.ok(&frame(frame::HEADERS, frame::END_HEADERS, 1, &first));
    let slot = match &happened[..] {
        [Happened::Request { slot, .. }] => *slot,
        other => panic!("{other:?}"),
    };
    let flags = frame::END_HEADERS | frame::END_STREAM;
    let happened = client.ok(&frame(frame::HEADERS, flags, 1, &[0xbe; 4000]));
    assert_eq!(cancelled(&happened), [slot]);
    assert_eq!(client.sent(), [reset(1, Reason::Protocol)]);
}

#[test]
fn rapid_resets_cancel_at_once_and_overdraw_the_budget() {
    let mut client = Client::new();
    let mut stream = 1;
    for _ in 0..BUDGET_BURST {
        let mut pair = headers(stream, &GET, true);
        pair.extend_from_slice(&rst_stream(stream));
        let happened = client.ok(&pair);
        assert_eq!(requests(&happened), 1);
        assert_eq!(cancelled(&happened), [0], "cancelled before the next frame");
        assert_eq!(client.session.engine.streams(), 0);
        stream += 2;
    }
    let mut pair = headers(stream, &GET, true);
    pair.extend_from_slice(&rst_stream(stream));
    assert_eq!(client.feed(&pair).err(), Some(Reason::EnhanceYourCalm));
}

#[test]
fn a_reset_after_the_answer_costs_nothing() {
    let mut client = Client::new();
    let mut stream = 1;
    for _ in 0..2 * BUDGET_BURST {
        let (slot, ..) = client.open(stream, &POST, false);
        client.respond(slot, 0);
        assert_eq!(cancelled(&client.ok(&rst_stream(stream))), [slot]);
        client.ok(&rst_stream(stream));
        stream += 2;
    }
}

#[test]
fn frames_that_cost_more_than_they_carry_overdraw_the_budget() {
    let unknown = frame(0x42, 0, 0, b"?");
    let priority = frame(frame::PRIORITY, 0, 1, &[0, 0, 0, 3, 16]);
    let empty_data = data(1, 0, false);
    let window_on_nothing = window_update(1, 0);
    let floods: [(&str, Vec<u8>); 6] = [
        ("PING", ping()),
        ("SETTINGS", settings(&[])),
        ("PRIORITY", priority),
        ("an unknown frame", unknown),
        ("DATA without data", empty_data),
        ("a stream error", window_on_nothing),
    ];
    for (what, flood) in floods {
        let mut client = Client::new();
        client.open(1, &POST, false);
        let mut allowed = 0;
        let failed = loop {
            // Each stream error resets a stream: keep one open.
            if what == "a stream error" && client.session.engine.streams() == 0 {
                client.open(1 + 2 * allowed, &POST, false);
            }
            let frame = match what {
                "a stream error" => window_update(1 + 2 * allowed, 0),
                _ => flood.clone(),
            };
            match client.feed(&frame) {
                Ok(_) => allowed += 1,
                Err(reason) => break reason,
            }
            client.sent();
        };
        assert_eq!(failed, Reason::EnhanceYourCalm, "{what}");
        assert_eq!(allowed, BUDGET_BURST, "{what}");
    }
}

#[test]
fn the_budget_refills_with_time() {
    let mut client = Client::new();
    for _ in 0..BUDGET_BURST {
        client.ok(&ping());
    }
    client.sent();
    client.session.engine.set_now(10);
    for _ in 0..10 * BUDGET_PER_SECOND {
        client.ok(&ping());
        client.sent();
    }
    assert_eq!(client.feed(&ping()).err(), Some(Reason::EnhanceYourCalm));

    let mut client = Client::new();
    client.session.engine.set_now(1_000_000);
    for _ in 0..BUDGET_BURST {
        client.ok(&ping());
        client.sent();
    }
    assert_eq!(
        client.feed(&ping()).err(),
        Some(Reason::EnhanceYourCalm),
        "the budget never exceeds its burst"
    );
}

#[test]
fn a_field_block_in_many_frames_is_bounded_in_frames_and_bytes() {
    let mut client = Client::new();
    let first = frame(frame::HEADERS, frame::END_STREAM, 1, &block(&GET));
    client.ok(&first);
    assert!(client.session.engine.in_block());
    let mut allowed = 0;
    let failed = loop {
        match client.feed(&frame(frame::CONTINUATION, 0, 1, b"")) {
            Ok(_) => allowed += 1,
            Err(reason) => break reason,
        }
    };
    assert_eq!((failed, allowed), (Reason::EnhanceYourCalm, BUDGET_BURST));

    // A block of exactly 64 KiB is accepted (and answered 431: it decodes to more than
    // the limit, counted with 32 bytes per field); a byte more ends the connection.
    let big = |last: usize| -> Vec<u8> {
        let fill = "v".repeat(16_000);
        let last = "v".repeat(last);
        let mut fields = GET.to_vec();
        fields.extend_from_slice(&[("x-fill", &*fill); 4]);
        fields.push(("x-fill", &*last));
        block(&fields)
    };
    let cut = |block: &[u8]| {
        let mut frames = frame(frame::HEADERS, frame::END_STREAM, 1, &block[..16_384]);
        let mut pieces = block[16_384..].chunks(16_384).peekable();
        while let Some(piece) = pieces.next() {
            let flags = match pieces.peek() {
                Some(_) => 0,
                None => frame::END_HEADERS,
            };
            frames.extend_from_slice(&frame(frame::CONTINUATION, flags, 1, piece));
        }
        frames
    };
    assert_eq!(big(1_420).len(), MAX_HEADER_LIST);
    let mut client = Client::new();
    let mut happened = client.ok(&cut(&big(1_420)));
    assert!(!client.session.engine.in_block());
    let Some(Happened::Request { begin, .. }) = happened.pop() else {
        panic!("a request that is answered");
    };
    assert_eq!(begin.preset, Some(Status::HEADER_FIELDS_TOO_LARGE));
    assert_eq!(
        Client::new().feed(&cut(&big(1_421))).err(),
        Some(Reason::EnhanceYourCalm)
    );
}

#[test]
fn streams_past_the_limit_are_refused() {
    let mut client = Client::with(2, 100);
    let first = client.get(1);
    client.get(3);
    assert!(client.ok(&headers(5, &GET, true)).is_empty());
    assert_eq!(client.sent(), [reset(5, Reason::RefusedStream)]);
    client.respond(first, 0);
    client.session.engine.finish(first);
    client.get(7);
    assert_eq!(
        client.session.engine.streams(),
        2,
        "an answered stream makes room"
    );
}

#[test]
fn frames_on_closed_streams_are_told_from_frames_on_their_way() {
    // Closed by both ends: more frames are an error (RFC 9113 5.1, closed), whether the
    // stream still lingers or not.
    let answered = |streams: u32| {
        let mut client = Client::new();
        for stream in (1..2 * streams).step_by(2) {
            let slot = client.get(stream);
            client.respond(slot, 0);
            client.session.engine.finish(slot);
        }
        client.sent();
        client
    };
    for streams in [1, 20] {
        let mut client = answered(streams);
        client.ok(&window_update(1, 1));
        assert!(client.sent().is_empty());
        client.ok(&data(1, 1, false));
        assert_eq!(client.sent(), [reset(1, Reason::StreamClosed)], "{streams}");
        client.ok(&window_update(1, 1));
        client.ok(&rst_stream(1));
        assert!(client.sent().is_empty());
    }
    for streams in [1, 20] {
        assert_eq!(
            answered(streams).feed(&headers(1, &GET, true)).err(),
            Some(Reason::StreamClosed),
            "{streams}"
        );
    }
    // While the answer is under way, the stream alone is at fault (half-closed).
    let mut client = Client::new();
    let slot = client.get(1);
    assert_eq!(cancelled(&client.ok(&headers(1, &GET, true))), [slot]);
    assert_eq!(client.sent(), [reset(1, Reason::StreamClosed)]);

    // Reset by the client: the same.
    let mut client = Client::new();
    client.get(1);
    client.ok(&rst_stream(1));
    client.ok(&data(1, 1, false));
    assert_eq!(client.sent(), [reset(1, Reason::StreamClosed)]);

    // Reset from this side: the client's frames were on their way, and a field block
    // among them still counts for the compression state.
    let mut client = Client::new();
    let mut bad = GET.to_vec();
    bad.push(("connection", "close"));
    client.ok(&headers(1, &bad, false));
    assert_eq!(client.sent(), [reset(1, Reason::Protocol)]);
    client.ok(&data(1, 100, false));
    let mut trailers = vec![0x40];
    length(&mut trailers, 1);
    trailers.push(b'k');
    length(&mut trailers, 1);
    trailers.push(b'v');
    let flags = frame::END_HEADERS | frame::END_STREAM;
    assert!(
        client
            .ok(&frame(frame::HEADERS, flags, 1, &trailers))
            .is_empty()
    );
    assert!(client.sent().is_empty());
    let mut next = block(&GET);
    next.push(0xbe);
    let mut happened = client.ok(&frame(frame::HEADERS, flags, 3, &next));
    let Some(Happened::Request { head, .. }) = happened.pop() else {
        panic!("a request");
    };
    assert!(head.fields.live().any(|(n, v, _)| (n, v) == (b"k", b"v")));

    // A stream number below one already used, never opened (RFC 9113 5.1.1).
    let mut client = Client::new();
    client.get(5);
    assert_eq!(
        client.feed(&headers(3, &GET, true)).err(),
        Some(Reason::Protocol)
    );
}

#[test]
fn the_rest_of_a_request_is_dropped_after_its_answer_up_to_a_point() {
    let mut client = Client::new();
    let answer = |client: &mut Client, stream: u32| {
        let (slot, ..) = client.open(stream, &POST, false);
        client.ok(&data(stream, 1000, false));
        client.respond(slot, 0);
        client.session.engine.finish(slot);
        client.sent();
    };

    // A short rest is taken and dropped: no reset, and the stream ends as usual.
    answer(&mut client, 1);
    client.ok(&data(1, 1000, true));
    assert!(client.sent().is_empty());

    // An invalid frame among it is still an error.
    answer(&mut client, 3);
    client.ok(&window_update(3, 0));
    assert_eq!(client.sent(), [reset(3, Reason::Protocol)]);

    // A long rest is stopped (RFC 9113 8.1), and what was on its way is ignored.
    answer(&mut client, 5);
    for _ in 0..4 {
        client.ok(&data(5, 16_000, false));
    }
    assert!(client.sent().is_empty(), "65 kB dropped");
    client.ok(&data(5, 16_000, false));
    assert_eq!(client.sent(), [reset(5, Reason::NoError)]);
    client.ok(&data(5, 16_000, true));
    assert!(client.sent().is_empty());

    // So is the oldest of more unfinished requests than linger.
    let mut client = Client::new();
    for stream in [1, 3, 5, 7, 9, 11, 13, 15] {
        answer(&mut client, stream);
    }
    let (slot, ..) = client.open(17, &POST, false);
    client.respond(slot, 0);
    client.session.engine.finish(slot);
    assert_eq!(client.sent().last(), Some(&reset(1, Reason::NoError)));

    let slot = client.get(19);
    client.session.engine.finish(slot);
    assert_eq!(
        client.sent(),
        [reset(19, Reason::Internal)],
        "work that ended without an answer"
    );
}

#[test]
fn a_stream_that_finished_out_of_turn_does_not_keep_the_others_waiting() {
    let mut client = Client::new();
    client.ok(&settings(&[(4, 1 << 20)]));
    let (first, second) = (client.get(1), client.get(3));
    client.respond(first, 70_000);
    client.respond(second, 10);
    // The connection's window (65,535) runs out under the first; both wait for it.
    let mut body = Bytes::from(vec![1u8; 70_000]);
    let mut small = Bytes::from(vec![2u8; 10]);
    let engine = &mut client.session.engine;
    assert!(!engine.send_data(first, &mut body, true));
    assert!(!engine.send_data(second, &mut small, true));
    client.sent();
    client.ready();

    client.ok(&window_update(0, 100_000));
    assert_eq!(client.ready(), [first]);
    // The second is polled first for another reason and finishes while still queued.
    let engine = &mut client.session.engine;
    assert!(engine.send_data(second, &mut small, true));
    engine.finish(second);
    assert!(engine.send_data(first, &mut body, true));
    engine.finish(first);
    assert_eq!(engine.streams(), 0);
}

#[test]
fn a_shutdown_announces_itself_then_names_the_last_stream() {
    let mut client = Client::new();
    let first = client.get(1);
    client.session.engine.start_shutdown();
    client.session.engine.start_shutdown();
    assert_eq!(
        client.sent(),
        [
            Sent::GoAway {
                last: (1 << 31) - 1,
                code: 0,
            },
            Sent::Ping {
                ack: false,
                opaque: b"shutdown".to_vec(),
            },
        ]
    );
    // A request the client sent before it read the GOAWAY is served.
    let second = client.get(3);
    assert!(client.session.engine.shutdown_announced());
    client.ok(&frame(frame::PING, frame::ACK, 0, b"shutdown"));
    assert_eq!(client.sent(), [Sent::GoAway { last: 3, code: 0 }]);
    assert!(client.ok(&headers(5, &GET, true)).is_empty());
    assert!(client.sent().is_empty(), "a later stream is ignored");

    assert!(!client.session.engine.finished());
    for slot in [first, second] {
        client.respond(slot, 0);
        client.session.engine.finish(slot);
    }
    assert!(client.session.engine.finished());

    let mut client = Client::new();
    client.ok(&frame(frame::GOAWAY, 0, 0, &[0; 8]));
    assert!(client.session.engine.finished(), "the client left");
}

#[test]
fn a_turn_given_to_a_stream_that_is_then_reset_passes_on() {
    let mut client = Client::new();
    client.ok(&settings(&[(4, 1 << 20)]));
    let (first, second) = (client.get(1), client.get(3));
    client.respond(first, 70_000);
    client.respond(second, 10_000);
    // The connection's window (65,535) runs out under the first; both wait for it.
    let mut one = Bytes::from(vec![1u8; 70_000]);
    let mut two = Bytes::from(vec![2u8; 10_000]);
    let engine = &mut client.session.engine;
    assert!(!engine.send_data(first, &mut one, true));
    assert!(!engine.send_data(second, &mut two, true));
    client.sent();
    client.ready();

    // The window opens and the first stream is reset before it used its turn.
    let mut frames = window_update(0, 1 << 20);
    frames.extend_from_slice(&rst_stream(1));
    assert_eq!(cancelled(&client.ok(&frames)), [first]);
    assert_eq!(client.ready(), [first, second]);
    assert!(client.session.engine.send_data(second, &mut two, true));
}

#[test]
fn streams_opened_after_the_final_goaway_are_ignored_whatever_they_send() {
    let mut client = Client::new();
    let slot = client.get(1);
    let engine = &mut client.session.engine;
    engine.start_shutdown();
    engine.finish_shutdown();
    client.sent();

    // Stream 3 was on its way: its request, its body and its trailers are dropped, and
    // the open stream goes on (RFC 9113 6.8).
    assert!(client.ok(&headers(3, &POST, false)).is_empty());
    client.ok(&data(3, 1000, false));
    client.ok(&window_update(3, 1));
    assert!(
        client
            .ok(&headers(3, &[("checksum", "x")], true))
            .is_empty()
    );
    client.ok(&rst_stream(5));
    assert!(client.sent().is_empty());
    assert_eq!(client.session.engine.streams(), 1);

    // A connection error after that still names stream 1 as the last one served.
    assert_eq!(
        client.feed(&window_update(0, 0)).err(),
        Some(Reason::Protocol)
    );
    client.session.engine.fail(Reason::Protocol);
    assert_eq!(client.sent(), [Sent::GoAway { last: 1, code: 1 }]);
    client.session.engine.finish(slot);
}

#[test]
fn a_slow_reader_holds_only_what_is_still_queued() {
    let mut client = Client::with(4, 100);
    client.ok(&settings(&[(4, 1 << 30)]));
    client.ok(&window_update(0, 1 << 30));
    client.sent();
    let mut responder = Responder::default();
    let path = [GET[0], GET[1], GET[2], (":path", "/123456789ab")];
    for stream in [1, 3, 5, 7] {
        let (slot, begin, head) = client.open(stream, &path, true);
        responder.request(slot, &begin, &head);
    }
    responder.run(&mut client.session, true);
    // The client takes 3000 bytes at a time: the streams refill the queue each time, so
    // it is never empty until all four bodies (108 kB each) are out.
    let mut wire = Vec::new();
    while !client.session.engine.out.is_empty() {
        wire.extend_from_slice(&client.session.written_up_to(3000));
        responder.run(&mut client.session, false);
        let out = &client.session.engine.out;
        assert!(
            out.held() <= out.len() + OUT_HIGH + 4096,
            "{} held",
            out.held()
        );
    }
    let mut got = [0usize; 8];
    for (head, payload) in harness::frames(&wire) {
        if head.kind == frame::DATA {
            assert!(payload.iter().all(|&b| b == b'x'));
            got[head.stream as usize] += payload.len();
        }
    }
    assert_eq!([got[1], got[3], got[5], got[7]], [108_000; 4]);
}

#[test]
fn a_stream_without_window_for_too_long_is_reset() {
    let mut client = Client::new();
    let slot = client.get(1);
    client.respond(slot, 100_000);
    let mut body = Bytes::from(vec![7u8; 100_000]);
    let engine = &mut client.session.engine;
    assert!(!engine.send_data(slot, &mut body, true));
    client.sent();
    let engine = &mut client.session.engine;
    let mut stalled = Vec::new();
    engine.set_now(50);
    engine.reset_stalled(-1, &mut stalled);
    assert!(stalled.is_empty(), "stalled since second 0");

    // A byte of window is progress: the wait starts over.
    client.ok(&window_update(0, 1));
    client.ok(&window_update(1, 1));
    let engine = &mut client.session.engine;
    assert!(!engine.send_data(slot, &mut body, true));
    assert_eq!(engine.stalled_since(), Some(50));
    engine.reset_stalled(49, &mut stalled);
    assert!(stalled.is_empty());
    client.sent();

    let engine = &mut client.session.engine;
    engine.reset_stalled(50, &mut stalled);
    assert_eq!(stalled, [slot]);
    engine.release(slot);
    assert_eq!(engine.streams(), 0);
    assert_eq!(engine.stalled_since(), None);
    assert_eq!(client.sent(), [reset(1, Reason::Cancel)]);
}

#[test]
fn a_client_that_does_not_read_gets_no_more_queued_than_the_high_mark() {
    let mut client = Client::with(4, 100);
    client.ok(&settings(&[(4, 1 << 30)]));
    client.ok(&window_update(0, 1 << 30));
    client.sent();
    let mut responder = Responder::default();
    // Four requests whose answers are 108 kB each (the responder sizes by path).
    let path = [GET[0], GET[1], GET[2], (":path", "/123456789ab")];
    for stream in [1, 3, 5, 7] {
        let (slot, begin, head) = client.open(stream, &path, true);
        responder.request(slot, &begin, &head);
    }
    responder.run(&mut client.session, true);
    let queued = client.session.engine.out.len();
    assert!(
        (OUT_HIGH..OUT_HIGH + 16_384 + 1024).contains(&queued),
        "{queued} bytes queued"
    );
    assert!(client.session.engine.congested());
    // Nothing is read from a client that takes nothing.
    assert!(client.ok(&ping()).is_empty());
    assert_eq!(client.session.engine.out.len(), queued);

    // As the client reads, the streams take turns until all four are done.
    let mut got = [0usize; 8];
    let mut ended = 0;
    for _ in 0..100 {
        for sent in client.sent() {
            if let Sent::Data { stream, len, end } = sent {
                got[stream as usize] += len;
                ended += usize::from(end);
            }
        }
        client.ok(b"");
        responder.run(&mut client.session, false);
    }
    assert_eq!(ended, 4);
    assert_eq!([got[1], got[3], got[5], got[7]], [108_000; 4]);
    assert_eq!(client.session.engine.streams(), 0);
}

#[test]
fn connection_errors() {
    let open_block = frame(frame::HEADERS, 0, 1, &block(&GET));
    let then = |after: Vec<u8>| [open_block.clone(), after].concat();
    let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
        ("DATA on stream 0", data(0, 1, false), Reason::Protocol),
        (
            "DATA on an idle stream",
            data(9, 1, false),
            Reason::Protocol,
        ),
        (
            "a frame larger than 16,384, judged by its header",
            vec![0, 0x40, 1, frame::DATA, 0, 0, 0, 0, 1],
            Reason::FrameSize,
        ),
        (
            "PUSH_PROMISE",
            frame(frame::PUSH_PROMISE, 4, 1, &[0, 0, 0, 2]),
            Reason::Protocol,
        ),
        (
            "CONTINUATION without HEADERS",
            frame(frame::CONTINUATION, 4, 1, b""),
            Reason::Protocol,
        ),
        (
            "a frame inside a field block",
            then(ping()),
            Reason::Protocol,
        ),
        (
            "CONTINUATION of another stream",
            then(frame(frame::CONTINUATION, 4, 3, b"")),
            Reason::Protocol,
        ),
        (
            "SETTINGS of 5 octets",
            frame(frame::SETTINGS, 0, 0, &[0; 5]),
            Reason::FrameSize,
        ),
        (
            "a SETTINGS ACK with a payload",
            frame(frame::SETTINGS, 1, 0, &[0; 6]),
            Reason::FrameSize,
        ),
        (
            "SETTINGS on a stream",
            frame(frame::SETTINGS, 0, 1, b""),
            Reason::Protocol,
        ),
        ("ENABLE_PUSH 2", settings(&[(2, 2)]), Reason::Protocol),
        (
            "MAX_FRAME_SIZE 100",
            settings(&[(5, 100)]),
            Reason::Protocol,
        ),
        (
            "MAX_FRAME_SIZE 2^24",
            settings(&[(5, 1 << 24)]),
            Reason::Protocol,
        ),
        (
            "PING of 7 octets",
            frame(frame::PING, 0, 0, &[0; 7]),
            Reason::FrameSize,
        ),
        (
            "PING on a stream",
            frame(frame::PING, 0, 1, &[0; 8]),
            Reason::Protocol,
        ),
        ("WINDOW_UPDATE of 0", window_update(0, 0), Reason::Protocol),
        (
            "WINDOW_UPDATE of 3 octets",
            frame(frame::WINDOW_UPDATE, 0, 0, &[0; 3]),
            Reason::FrameSize,
        ),
        (
            "a connection window past 2^31-1",
            window_update(0, (1 << 31) - 1),
            Reason::FlowControl,
        ),
        (
            "WINDOW_UPDATE on an idle stream",
            window_update(9, 1),
            Reason::Protocol,
        ),
        (
            "RST_STREAM of 3 octets",
            frame(frame::RST_STREAM, 0, 1, &[0; 3]),
            Reason::FrameSize,
        ),
        ("RST_STREAM on stream 0", rst_stream(0), Reason::Protocol),
        (
            "RST_STREAM on an idle stream",
            rst_stream(9),
            Reason::Protocol,
        ),
        (
            "GOAWAY of 4 octets",
            frame(frame::GOAWAY, 0, 0, &[0; 4]),
            Reason::FrameSize,
        ),
        (
            "HEADERS on stream 0",
            headers(0, &GET, true),
            Reason::Protocol,
        ),
        (
            "HEADERS on an even stream",
            headers(2, &GET, true),
            Reason::Protocol,
        ),
        (
            "padding longer than the payload",
            frame(frame::DATA, frame::PADDED, 1, &[5, 0, 0]),
            Reason::Protocol,
        ),
        (
            "a field block that does not decode",
            frame(frame::HEADERS, 5, 1, &[0x80]),
            Reason::Compression,
        ),
    ];
    for (what, bytes, reason) in cases {
        assert_eq!(Client::new().feed(&bytes).err(), Some(reason), "{what}");
    }

    let mut session = Session::new(128, 100);
    assert_eq!(
        session.feed(b"GET / HTTP/1.1\r\n").err(),
        Some(Reason::Protocol),
        "not the preface"
    );
    let mut session = Session::new(128, 100);
    let mut hello = frame::PREFACE.to_vec();
    hello.extend_from_slice(&ping());
    assert_eq!(
        session.feed(&hello).err(),
        Some(Reason::Protocol),
        "SETTINGS comes first"
    );
}

#[test]
fn stream_errors_reset_the_stream_alone() {
    let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
        ("WINDOW_UPDATE of 0", window_update(1, 0), Reason::Protocol),
        (
            "a stream window past 2^31-1",
            window_update(1, (1 << 31) - 1),
            Reason::FlowControl,
        ),
        (
            "PRIORITY of 4 octets",
            frame(frame::PRIORITY, 0, 1, &[0; 4]),
            Reason::FrameSize,
        ),
        (
            "PRIORITY that depends on its own stream",
            frame(frame::PRIORITY, 0, 1, &[0, 0, 0, 1, 16]),
            Reason::Protocol,
        ),
    ];
    for (what, bytes, reason) in cases {
        let mut client = Client::new();
        let slot = client.get(1);
        assert_eq!(cancelled(&client.ok(&bytes)), [slot], "{what}");
        assert_eq!(client.sent(), [reset(1, reason)], "{what}");
        assert_eq!(client.get(3), slot, "{what}: the connection goes on");
    }

    // A stream that does not exist cannot be reset: the connection is at fault for an
    // idle one, and a closed one is left alone.
    let self_dependent = frame(frame::PRIORITY, 0, 5, &[0, 0, 0, 5, 16]);
    assert_eq!(
        Client::new().feed(&self_dependent).err(),
        Some(Reason::Protocol)
    );
    let short = frame(frame::PRIORITY, 0, 5, &[0; 4]);
    assert_eq!(Client::new().feed(&short).err(), Some(Reason::FrameSize));
    let mut client = Client::new();
    client.get(5);
    client.ok(&rst_stream(5));
    client.ok(&self_dependent);
    assert!(client.sent().is_empty());

    // HEADERS whose priority fields name the stream itself (RFC 9113 5.3.1).
    let mut client = Client::new();
    let mut payload = vec![0, 0, 0, 1, 16];
    payload.extend_from_slice(&block(&GET));
    let flags = frame::END_HEADERS | frame::END_STREAM | frame::PRIORITY_FLAG;
    assert!(
        client
            .ok(&frame(frame::HEADERS, flags, 1, &payload))
            .is_empty()
    );
    assert_eq!(client.sent(), [reset(1, Reason::Protocol)]);
    payload[3] = 0;
    assert_eq!(
        requests(&client.ok(&frame(frame::HEADERS, flags, 3, &payload))),
        1
    );
}

#[test]
fn a_response_head_larger_than_a_frame_continues() {
    let mut client = Client::new();
    let slot = client.get(1);
    let mut fields = Fields::default();
    fields.push(b"x-big", &[b'a'; 40_000]);
    let engine = &mut client.session.engine;
    engine.send_head(slot, Status::OK, &fields, None, None, true);
    let written = client.session.written();
    let kinds: Vec<_> = harness::frames(&written)
        .iter()
        .map(|(head, _)| (head.kind, head.flags, head.stream))
        .collect();
    assert_eq!(
        kinds,
        [
            (frame::HEADERS, frame::END_STREAM, 1),
            (frame::CONTINUATION, 0, 1),
            (frame::CONTINUATION, frame::END_HEADERS, 1),
        ]
    );
}

#[test]
fn a_repeated_head_is_sent_as_the_same_small_block_and_others_are_not_mistaken_for_it() {
    fn head(fields: &[(&str, &str)]) -> Fields {
        let mut head = Fields::default();
        for (name, value) in fields {
            head.push(name.as_bytes(), value.as_bytes());
        }
        head
    }
    fn expected(fields: &[(&str, &str)], length: u64, date: &[u8]) -> Vec<(String, String)> {
        let length = length.to_string();
        let mut all = vec![(":status", "200")];
        all.extend_from_slice(fields);
        all.push(("content-length", &length));
        all.push(("date", std::str::from_utf8(date).unwrap()));
        pairs(&all)
    }
    let mut client = Client::new();
    let mut stream = 1;
    // Answers a request and returns the head a client decodes and the size of its block.
    let mut answer = |client: &mut Client, head: &Fields, length: u64, date: &[u8]| {
        let slot = client.get(stream);
        stream += 2;
        let engine = &mut client.session.engine;
        engine.send_head(slot, Status::OK, head, Some(length), Some(date), true);
        engine.finish(slot);
        let written = client.session.written();
        let block = harness::frames(&written)[0].1.clone();
        let mut decoded = Vec::new();
        client
            .decoder
            .decode(&block, |name, value| {
                decoded.push((
                    String::from_utf8(name.to_vec()).unwrap(),
                    String::from_utf8(value.to_vec()).unwrap(),
                ));
            })
            .expect("the block decodes");
        (decoded, block.len())
    };
    const PAGE: [(&str, &str); 3] = [
        ("content-type", "text/html"),
        ("etag", "\"v1\""),
        ("x-frame-options", "DENY"),
    ];
    let page = head(&PAGE);
    let noon = b"Sun, 06 Nov 1994 12:00:00 GMT";
    let later = b"Sun, 06 Nov 1994 12:00:01 GMT";

    let sizes: Vec<_> = (0..5)
        .map(|_| {
            let (decoded, size) = answer(&mut client, &page, 1024, noon);
            assert_eq!(decoded, expected(&PAGE, 1024, noon));
            size
        })
        .collect();
    assert!(sizes[0] > 50, "literals first: {sizes:?}");
    assert_eq!(sizes[2..], [6, 6, 6], "then one byte per field: {sizes:?}");

    // A head that differs from the kept one in a single respect gets its own block, sent
    // right after the kept block was used, and the first head still gets its own after it.
    let style = [PAGE[1], PAGE[2], ("content-type", "text/css")];
    let other_etag = [PAGE[0], ("etag", "\"v2\""), PAGE[2]];
    // The same bytes, cut into name and value one byte earlier.
    let cut = [PAGE[0], PAGE[1], ("x-frame-option", "sDENY")];
    // A field removed after it was added, as a site's header rule does: its bytes stay.
    let mut removed = head(&PAGE);
    removed.remove(&crate::msg::HeaderName::new("x-frame-options").unwrap());
    let variants = [
        (
            "another length",
            head(&PAGE),
            1025,
            noon,
            expected(&PAGE, 1025, noon),
        ),
        (
            "another date",
            head(&PAGE),
            1024,
            later,
            expected(&PAGE, 1024, later),
        ),
        (
            "another value",
            head(&style),
            1024,
            noon,
            expected(&style, 1024, noon),
        ),
        (
            "another value of the same length",
            head(&other_etag),
            1024,
            noon,
            expected(&other_etag, 1024, noon),
        ),
        (
            "another cut",
            head(&cut),
            1024,
            noon,
            expected(&cut, 1024, noon),
        ),
        (
            "a field removed",
            removed,
            1024,
            noon,
            expected(&PAGE[..2], 1024, noon),
        ),
    ];
    for (what, fields, length, date, expected_head) in variants {
        for _ in 0..3 {
            let (decoded, _) = answer(&mut client, &page, 1024, noon);
            assert_eq!(decoded, expected(&PAGE, 1024, noon), "before {what}");
        }
        let (decoded, size) = answer(&mut client, &page, 1024, noon);
        assert_eq!((decoded, size), (expected(&PAGE, 1024, noon), 6), "{what}");
        let (decoded, _) = answer(&mut client, &fields, length, date);
        assert_eq!(decoded, expected_head, "{what}");
    }

    // A table size the client changes is announced once, in the next block (RFC 7541 4.2),
    // however often the head before it was repeated: 3 bytes for a size of 1000.
    client.ok(&settings(&[(1, 1000)]));
    client.sent();
    let sizes: Vec<_> = (0..4)
        .map(|_| {
            let (decoded, size) = answer(&mut client, &page, 1024, noon);
            assert_eq!(decoded, expected(&PAGE, 1024, noon));
            size
        })
        .collect();
    assert_eq!(sizes, [9, 6, 6, 6]);

    // Without a table, every field is a literal again.
    client.ok(&settings(&[(1, 0)]));
    client.sent();
    for _ in 0..3 {
        let (decoded, size) = answer(&mut client, &page, 1024, noon);
        assert_eq!(decoded, expected(&PAGE, 1024, noon));
        assert!(size > 50, "{size} bytes");
    }
}

#[test]
fn heads_that_differ_in_status_alone_are_told_apart() {
    let mut client = Client::new();
    let mut fields = Fields::default();
    fields.push(b"content-type", b"text/html");
    let mut stream = 1;
    let mut answer = |client: &mut Client, status: Status| {
        let slot = client.get(stream);
        stream += 2;
        let engine = &mut client.session.engine;
        engine.send_head(slot, status, &fields, None, None, true);
        engine.finish(slot);
        match &client.sent()[..] {
            [Sent::Headers { fields, .. }] => fields[0].1.clone(),
            other => panic!("{other:?}"),
        }
    };
    // 200 and 404 are both in the static table: neither changes the encoder's.
    for _ in 0..4 {
        assert_eq!(answer(&mut client, Status::OK), "200");
    }
    assert_eq!(answer(&mut client, Status::NOT_FOUND), "404");
    assert_eq!(answer(&mut client, Status::OK), "200");
}

#[test]
fn the_clients_table_size_limit_is_honoured() {
    let mut client = Client::new();
    client.ok(&settings(&[(1, 0)]));
    client.sent();
    let mut fields = Fields::default();
    fields.push(b"server", b"x");
    for stream in [1, 3, 5] {
        let slot = client.get(stream);
        let engine = &mut client.session.engine;
        engine.send_head(slot, Status::OK, &fields, None, None, true);
        engine.finish(slot);
        let written = client.session.written();
        let frames = harness::frames(&written);
        let block = &frames[0].1;
        // 0x20 is a table size update to 0 (RFC 7541 6.3), due in the first block after
        // the setting; with no table, the field stays a literal (0x00 + name index 54).
        let expected: &[u8] = match stream {
            1 => &[0x20, 0x88, 0x0f, 0x27, 0x01, b'x'],
            _ => &[0x88, 0x0f, 0x27, 0x01, b'x'],
        };
        assert_eq!(block, expected, "stream {stream}");
    }
}

mod any_client {
    use super::super::harness;
    use super::{GET, POST, frame};
    use proptest::prelude::*;

    /// A frame a client might send: mostly well-formed, on a handful of streams.
    fn a_frame() -> impl Strategy<Value = Vec<u8>> {
        let stream = prop_oneof![Just(0u32), (0u32..6).prop_map(|n| 2 * n + 1), 0u32..12];
        let block = prop_oneof![
            Just(super::block(&GET)),
            Just(super::block(&POST)),
            Just(super::block(&[
                GET[0],
                GET[1],
                GET[2],
                (":path", "/123456789ab")
            ])),
            Just(super::block(&[("trailer", "x")])),
            Just(vec![
                0x82, 0x87, 0x84, 0x41, 0x01, b'a', 0x40, 0x01, b'k', 0x01, b'v'
            ]),
            Just(vec![0x82, 0x87, 0x84, 0xbe, 0xbf]),
            proptest::collection::vec(any::<u8>(), 0..24),
        ];
        let increment = prop_oneof![Just(0u32), Just(1), Just(70_000), Just((1 << 31) - 1)];
        let window = prop_oneof![Just(0u32), Just(1), Just(65_535), Just(1 << 20)];
        prop_oneof![
            (stream.clone(), block.clone(), any::<u8>()).prop_map(|(s, b, flags)| super::frame(
                frame::HEADERS,
                flags & 0x05,
                s,
                &b
            )),
            (stream.clone(), block, any::<bool>()).prop_map(|(s, b, end)| super::frame(
                frame::CONTINUATION,
                if end { frame::END_HEADERS } else { 0 },
                s,
                &b
            )),
            (stream.clone(), 0usize..33, any::<bool>()).prop_map(|(s, len, end)| super::data(
                s,
                len * 500,
                end
            )),
            stream.clone().prop_map(super::rst_stream),
            (stream.clone(), increment).prop_map(|(s, by)| super::window_update(s, by)),
            window.prop_map(|w| super::settings(&[(4, w)])),
            (0u32..5000).prop_map(|size| super::settings(&[(1, size)])),
            Just(super::ping()),
            Just(super::frame(frame::PING, frame::ACK, 0, b"shutdown")),
            (stream, proptest::collection::vec(any::<u8>(), 0..8))
                .prop_map(|(s, payload)| super::frame(frame::PRIORITY, 0, s, &payload)),
            proptest::collection::vec(any::<u8>(), 0..30),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1500))]

        /// Whatever a client sends, in whatever reads, and whether or not it reads the
        /// answers: no panic, bounded output, whole frames, blocks that decode (the checks
        /// are the harness's).
        #[test]
        fn frames_in_any_order_keep_the_engine_within_its_limits(
            frames in proptest::collection::vec(a_frame(), 0..60),
            cut in 1usize..200,
            reads_answers in any::<bool>(),
        ) {
            let bytes = frames.concat();
            let mut input = vec![u8::from(!reads_answers)];
            for read in bytes.chunks(cut) {
                input.push(read.len() as u8);
                input.extend_from_slice(read);
            }
            harness::frames_input(&input);
        }

        /// Requests for a few resources over and over, between changes of the client's
        /// table size: every response head decodes to what was sent (the harness checks),
        /// whether it was encoded afresh or sent as the block kept from the last time.
        #[test]
        fn repeated_answers_decode_to_what_was_sent(
            steps in proptest::collection::vec(
                prop_oneof![
                    8 => (0usize..3).prop_map(Ok),
                    1 => prop_oneof![Just(0u32), Just(60), Just(200), Just(4096)].prop_map(Err),
                ],
                1..80,
            ),
            cut in 1usize..200,
        ) {
            let paths = ["/", "/ab", "/123456789ab"];
            let mut bytes = Vec::new();
            for (n, step) in steps.into_iter().enumerate() {
                match step {
                    Ok(path) => {
                        let fields = [GET[0], GET[1], GET[2], (":path", paths[path])];
                        bytes.extend_from_slice(&super::headers(2 * n as u32 + 1, &fields, true));
                        // Room for the answer, whatever its size.
                        bytes.extend_from_slice(&super::window_update(0, 1 << 20));
                    }
                    Err(size) => bytes.extend_from_slice(&super::settings(&[(1, size), (4, 1 << 20)])),
                }
            }
            let mut input = vec![0];
            for read in bytes.chunks(cut) {
                input.push(read.len() as u8);
                input.extend_from_slice(read);
            }
            harness::frames_input(&input);
        }

        #[test]
        fn field_blocks_survive_decoding_and_encoding(
            blocks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..8),
        ) {
            for block in blocks {
                harness::hpack_input(&block);
            }
        }
    }
}

mod driver {
    use crate::net::Socket;
    use crate::proxy::tls::ClientStream;
    use crate::runtime::testing::{free_addr, plan_from, served};
    use crate::runtime::{Generation, TlsState, allowed_cpus, spawn_workers, stop};
    use crate::tls::{self, TicketKeys};
    use bytes::Bytes;
    use std::sync::Arc;
    use std::time::Instant;

    /// One core with an HTTPS listener whose site answers every request with `hi`.
    fn generation(addr: std::net::SocketAddr) -> Arc<Generation> {
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [], "https": [addr] },
                "sites": [{
                    "name": "test",
                    "hosts": ["test.example"],
                    "tls": {
                        "cert": "/nonexistent/fullchain.pem",
                        "key": "/nonexistent/key.pem",
                        "redirectHttp": false,
                        "http3": false,
                    },
                    "routes": [{ "respond": { "body": "hi" } }],
                }],
            }),
        );
        let (certs, _) = tls::load(&plan.certs, None);
        Arc::new(Generation {
            plan: Arc::new(plan),
            tls: Some(TlsState {
                certs: Arc::new(certs),
                tickets: Arc::new(TicketKeys::generate(3600)),
            }),
            access: Arc::default(),
        })
    }

    async fn client(addr: std::net::SocketAddr) -> ::h2::client::SendRequest<Bytes> {
        let mut config = (*tls::client_config(false)).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let sock = Socket::connect(addr).await.unwrap();
        let name = "test.example".try_into().unwrap();
        let io = ClientStream::connect(sock, Arc::new(config), name)
            .await
            .unwrap();
        let (send, conn) = ::h2::client::handshake(io).await.unwrap();
        tokio::spawn(conn);
        send
    }

    /// Fields a browser sends with a navigation.
    const BROWSER: &[(&str, &str)] = &[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("cookie", "session=0123456789abcdef; theme=dark"),
        ("cookie", "lang=en"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("upgrade-insecure-requests", "1"),
        ("priority", "u=0, i"),
    ];

    async fn get(send: &mut ::h2::client::SendRequest<Bytes>, fields: &[(&str, &str)]) {
        std::future::poll_fn(|cx| send.poll_ready(cx))
            .await
            .unwrap();
        let mut req = http::Request::get("https://test.example/");
        for (name, value) in fields {
            req = req.header(*name, *value);
        }
        let req = req.body(()).unwrap();
        let (response, _) = send.send_request(req, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        let mut got = Vec::new();
        while let Some(data) = body.data().await {
            got.extend_from_slice(&data.unwrap());
        }
        assert_eq!(got, b"hi");
    }

    /// Allocations the core thread makes on a warm keep-alive connection: none per stream.
    /// The few there are come with the clock: each new second's Date enters the response
    /// table, whose buffers grow a handful of times before the table wraps.
    #[test]
    fn allocations_per_stream() {
        let addr = free_addr();
        let workers = spawn_workers(&[allowed_cpus()[0]], generation(addr)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let streams = 10_000;
        let measured = runtime.block_on(async {
            let mut send = client(addr).await;
            let mut measured = Vec::new();
            for fields in [&[][..], BROWSER] {
                for _ in 0..2_000 {
                    get(&mut send, fields).await;
                }
                let before = served(addr.port(), 0).allocations;
                for _ in 0..streams {
                    get(&mut send, fields).await;
                }
                let after = served(addr.port(), 0).allocations;
                measured.push(after - before);
            }
            measured
        });
        stop(workers, Instant::now());
        println!(
            "core thread allocations in {streams} h2 streams: {} without fields, {} with a \
             browser's {}",
            measured[0],
            measured[1],
            BROWSER.len()
        );
        assert!(
            measured
                .iter()
                .all(|&allocations| allocations < streams / 100),
            "{measured:?} allocations in {streams} streams"
        );
    }
}
