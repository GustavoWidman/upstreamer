//! The server-side TLS transport over loopback sockets: `accept` and `Transport::Tls` against a
//! rustls client (and openssl and curl when they are installed).

use super::*;
use crate::net::Socket;
use rustls::crypto::aws_lc_rs::cipher_suite as suites;
use rustls::{ClientConnection, HandshakeKind, StreamOwned, SupportedCipherSuite};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn fixture_source(stem: &str, names: &[&str]) -> CertSource {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    CertSource {
        cert: dir.join(format!("{stem}.crt")),
        key: dir.join(format!("{stem}.key")),
        names: names.iter().map(|n| Box::from(*n)).collect(),
    }
}

fn fixture_der(stem: &str) -> CertificateDer<'static> {
    let pem = std::fs::read(fixture_source(stem, &[]).cert).unwrap();
    CertificateDer::pem_slice_iter(&pem)
        .next()
        .unwrap()
        .unwrap()
}

fn store() -> Arc<CertStore> {
    let sources = [
        fixture_source("apex", &["example.test"]),
        fixture_source("wild", &["*.example.test"]),
        fixture_source("a", &["a.test"]),
        fixture_source("missing", &["new.test"]),
    ];
    Arc::new(load(&sources, None).0)
}

fn server(store: &Arc<CertStore>) -> Arc<rustls::ServerConfig> {
    server_config(store.clone(), Arc::new(TicketKeys::generate(3600)))
}

struct Client {
    config: Arc<rustls::ClientConfig>,
}

impl Client {
    fn new(alpn: &[&[u8]]) -> Client {
        Client::with(alpn, None)
    }
    /// Only `suite` on offer (and so only its protocol version).
    fn with(alpn: &[&[u8]], suite: Option<SupportedCipherSuite>) -> Client {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if let Some(suite) = suite {
            provider.cipher_suites = vec![suite];
        }
        let provider = Arc::new(provider);
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert { provider }))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Client {
            config: Arc::new(config),
        }
    }
    fn connect(&self, addr: SocketAddr, sni: &str) -> StreamOwned<ClientConnection, TcpStream> {
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        let conn = ClientConnection::new(self.config.clone(), name).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).unwrap();
        }
        stream
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Runs `client` on its own thread against one accepted connection that `server` handles on
/// this thread's runtime.
fn run<C: Send + 'static, R>(
    client: impl FnOnce(SocketAddr) -> C + Send + 'static,
    server: impl AsyncFnOnce(Socket) -> R,
) -> (R, C) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::thread::spawn(move || client(addr));
    let (tcp, _) = listener.accept().unwrap();
    tcp.set_nonblocking(true).unwrap();
    let served = runtime().block_on(async move {
        let sock = Socket::from_fd(tcp.into()).unwrap();
        server(sock).await
    });
    (served, client.join().unwrap())
}

async fn accepted(sock: Socket, config: Arc<rustls::ServerConfig>) -> (Transport, Proto) {
    accept(sock, config).await.expect("handshake")
}

/// Reads until `want` bytes arrived or the stream ended.
async fn read_exactly(io: &mut Transport, want: usize) -> Vec<u8> {
    let mut buf = BytesMut::new();
    while buf.len() < want {
        if io.read(&mut buf).await.unwrap() == 0 {
            break;
        }
    }
    buf.to_vec()
}

/// Bytes with no period that lines up with record or chunk sizes.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn sni_selects_exact_wildcard_and_self_signed_certificates() {
    let store = store();
    let self_signed = store.get("new.test").unwrap();
    assert_eq!(self_signed.origin, Origin::SelfSigned);
    let cases = [
        ("example.test", fixture_der("apex")),
        ("www.example.test", fixture_der("wild")),
        ("a.test", fixture_der("a")),
        ("new.test", self_signed.key.cert[0].clone()),
    ];
    for (sni, expected) in cases {
        let config = server(&store);
        let (echoed, (cert, reply)) = run(
            move |addr| {
                let mut tls = Client::new(&[]).connect(addr, sni);
                tls.write_all(b"ping").unwrap();
                let mut reply = [0u8; 4];
                tls.read_exact(&mut reply).unwrap();
                (tls.conn.peer_certificates().unwrap()[0].clone(), reply)
            },
            async |sock| {
                let (mut io, _) = accepted(sock, config).await;
                let got = read_exactly(&mut io, 4).await;
                io.write_all_vectored(&mut [IoSlice::new(&got)])
                    .await
                    .unwrap();
                got
            },
        );
        assert_eq!(cert, expected, "{sni}");
        assert_eq!((&echoed[..], &reply), (&b"ping"[..], b"ping"), "{sni}");
    }
}

#[test]
fn unknown_name_gets_an_alert_and_a_handshake_error() {
    let config = server(&store());
    let (served, client_err) = run(
        |addr| {
            let name = ServerName::try_from("other.test").unwrap();
            let conn = ClientConnection::new(Client::new(&[]).config, name).unwrap();
            let mut stream = StreamOwned::new(conn, TcpStream::connect(addr).unwrap());
            stream.write_all(b"x").unwrap_err()
        },
        async |sock| accept(sock, config).await.err(),
    );
    assert!(matches!(served, Some(TlsError::Handshake(_))), "{served:?}");
    let alert = client_err.into_inner().unwrap();
    assert_eq!(
        alert.downcast_ref::<rustls::Error>(),
        Some(&rustls::Error::AlertReceived(
            rustls::AlertDescription::AccessDenied
        ))
    );
}

#[test]
fn alpn_result_is_reported() {
    let store = store();
    type Offer = &'static [&'static [u8]];
    let cases: [(Offer, Proto); 4] = [
        (&[b"h2", b"http/1.1"], Proto::H2),
        (&[b"http/1.1", b"h2"], Proto::H2),
        (&[b"http/1.1"], Proto::H1),
        (&[], Proto::H1),
    ];
    for (offer, expected) in cases {
        let config = server(&store);
        let (proto, chosen) = run(
            move |addr| {
                let tls = Client::new(offer).connect(addr, "a.test");
                tls.conn.alpn_protocol().map(<[u8]>::to_vec)
            },
            async |sock| accepted(sock, config).await.1,
        );
        assert!(
            matches!(
                (proto, expected),
                (Proto::H2, Proto::H2) | (Proto::H1, Proto::H1)
            ),
            "offered {offer:?}"
        );
        let expected_alpn = match expected {
            Proto::H2 => Some(b"h2".to_vec()),
            _ if offer.is_empty() => None,
            _ => Some(b"http/1.1".to_vec()),
        };
        assert_eq!(chosen, expected_alpn, "offered {offer:?}");
    }
}

const MIB: usize = 1 << 20;

/// 1 MiB up in 7777-byte client writes, then 1 MiB down in uneven server slices.
fn echo_mib(suite: Option<SupportedCipherSuite>) {
    let config = server(&store());
    let payload = pattern(MIB);
    let expected = payload.clone();
    let (received, echoed) = run(
        move |addr| {
            let mut tls = Client::with(&[], suite).connect(addr, "a.test");
            for chunk in payload.chunks(7777) {
                tls.write_all(chunk).unwrap();
            }
            let mut back = vec![0u8; MIB];
            tls.read_exact(&mut back).unwrap();
            back
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let got = read_exactly(&mut io, MIB).await;
            let (a, rest) = got.split_at(3);
            let (b, c) = rest.split_at(40_000);
            io.write_all_vectored(&mut [
                IoSlice::new(a),
                IoSlice::new(&[]),
                IoSlice::new(b),
                IoSlice::new(c),
            ])
            .await
            .unwrap();
            got
        },
    );
    assert!(received == expected, "server received every byte in order");
    assert!(echoed == expected, "client received every byte in order");
}

#[test]
fn mib_echo_tls13_aes128() {
    echo_mib(Some(suites::TLS13_AES_128_GCM_SHA256));
}

#[test]
fn mib_echo_tls13_aes256() {
    echo_mib(Some(suites::TLS13_AES_256_GCM_SHA384));
}

#[test]
fn mib_echo_tls13_chacha() {
    echo_mib(Some(suites::TLS13_CHACHA20_POLY1305_SHA256));
}

#[test]
fn mib_echo_tls12_aes128() {
    echo_mib(Some(suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
}

#[test]
fn mib_echo_tls12_aes256() {
    echo_mib(Some(suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384));
}

#[test]
fn mib_echo_tls12_chacha() {
    echo_mib(Some(suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256));
}

/// The ciphertext bytes that reach the client after the handshake.
struct Counting {
    tcp: TcpStream,
    read: Arc<AtomicUsize>,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.tcp.read(buf)?;
        self.read.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[test]
fn a_vectored_write_becomes_full_records() {
    // TLS 1.3 record: 5-byte header + plaintext + 1 content-type byte + 16-byte tag.
    const OVERHEAD: usize = 22;
    let config = server(&store());
    let head = pattern(300);
    let body = pattern(2 * 16384 + 1000);
    let mut expected = head.clone();
    expected.extend_from_slice(&body);
    let total = expected.len();
    let ((), (wire, got)) = run(
        move |addr| {
            let tls =
                Client::with(&[], Some(suites::TLS13_AES_128_GCM_SHA256)).connect(addr, "a.test");
            let read = Arc::new(AtomicUsize::new(0));
            let counting = Counting {
                tcp: tls.sock,
                read: read.clone(),
            };
            let mut tls = StreamOwned::new(tls.conn, counting);
            // The first round trip also carries the session ticket; the payload is only sent
            // after the second message, so the count starts clean.
            tls.write_all(b"go").unwrap();
            tls.read_exact(&mut [0u8; 2]).unwrap();
            read.store(0, Ordering::Relaxed);
            tls.write_all(b"more").unwrap();
            let mut got = vec![0u8; total];
            tls.read_exact(&mut got).unwrap();
            (read.load(Ordering::Relaxed), got)
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            assert_eq!(read_exactly(&mut io, 2).await, b"go");
            io.write_all_vectored(&mut [IoSlice::new(b"ok")])
                .await
                .unwrap();
            assert_eq!(read_exactly(&mut io, 4).await, b"more");
            let mut parts = [
                IoSlice::new(&head[..100]),
                IoSlice::new(&head[100..]),
                IoSlice::new(&body),
            ];
            io.write_all_vectored(&mut parts).await.unwrap();
        },
    );
    assert!(got == expected);
    assert_eq!(
        wire,
        total + 3 * OVERHEAD,
        "300 + 2 * 16384 + 1000 bytes in three records: 16384, 16384, 1300"
    );
}

/// Seals `data` with the client's keys into one record without sending it.
fn sealed_record(tls: &mut StreamOwned<ClientConnection, TcpStream>, data: &[u8]) -> Vec<u8> {
    tls.conn.writer().write_all(data).unwrap();
    let mut wire = Vec::new();
    while tls.conn.wants_write() {
        tls.conn.write_tls(&mut wire).unwrap();
    }
    wire
}

#[test]
fn a_record_split_across_reads_is_delivered_whole() {
    let config = server(&store());
    let (reads, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            let one = sealed_record(&mut tls, b"first request");
            let two = sealed_record(&mut tls, b"second");
            let three = sealed_record(&mut tls, b"third, split");
            // Inside the header, inside the body, then the rest with two more records, the
            // last one cut short.
            for piece in [&one[..3], &one[3..20]] {
                tls.sock.write_all(piece).unwrap();
                std::thread::sleep(Duration::from_millis(50));
            }
            let mut rest = one[20..].to_vec();
            rest.extend_from_slice(&two);
            rest.extend_from_slice(&three[..10]);
            tls.sock.write_all(&rest).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            tls.sock.write_all(&three[10..]).unwrap();
            let _ = tls.read_to_end(&mut Vec::new());
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let mut reads: Vec<Vec<u8>> = Vec::new();
            let mut buf = BytesMut::new();
            while reads.concat().len() < 31 {
                let n = io.read(&mut buf).await.unwrap();
                reads.push(buf.split_to(n).to_vec());
            }
            io.close().await;
            reads
        },
    );
    assert_eq!(reads.concat(), b"first requestsecondthird, split");
    let records = [&b"first request"[..], b"second", b"third, split"];
    let mut at = 0;
    for read in &reads {
        at += read.len();
        let mut end = 0;
        assert!(
            records.iter().any(|r| {
                end += r.len();
                end == at
            }),
            "every read ends at a record boundary: {reads:?}"
        );
    }
}

#[test]
fn readable_does_not_wait_for_a_record_already_buffered() {
    use tokio::io::AsyncReadExt;
    let config = server(&store());
    let (second, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            let mut both = sealed_record(&mut tls, b"a");
            both.extend_from_slice(&sealed_record(&mut tls, b"b"));
            tls.sock.write_all(&both).unwrap();
            let _ = tls.read_to_end(&mut Vec::new());
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let mut one = [0u8; 1];
            io.read_exact(&mut one).await.unwrap();
            assert_eq!(&one, b"a");
            tokio::time::timeout(Duration::from_millis(500), io.readable())
                .await
                .expect("the second record is already here")
                .unwrap();
            io.read_exact(&mut one).await.unwrap();
            io.close().await;
            one
        },
    );
    assert_eq!(&second, b"b");
}

#[test]
fn server_close_sends_close_notify() {
    let config = server(&store());
    let ((), (n, rest)) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            let mut rest = Vec::new();
            let n = tls.read_to_end(&mut rest);
            (n.map_err(|e| e.kind()), rest)
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            io.write_all_vectored(&mut [IoSlice::new(b"bye")])
                .await
                .unwrap();
            io.close().await;
        },
    );
    // rustls reports a TCP close without close_notify as UnexpectedEof.
    assert_eq!((n, &rest[..]), (Ok(3), &b"bye"[..]));
}

#[test]
fn poll_shutdown_sends_close_notify() {
    use tokio::io::AsyncWriteExt;
    let config = server(&store());
    let ((), (n, rest)) = run(
        |addr| {
            let mut tls = Client::new(&[b"h2"]).connect(addr, "a.test");
            let mut rest = Vec::new();
            let n = tls.read_to_end(&mut rest);
            (n.map_err(|e| e.kind()), rest)
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            io.write_all(b"frame").await.unwrap();
            io.shutdown().await.unwrap();
        },
    );
    assert_eq!((n, &rest[..]), (Ok(5), &b"frame"[..]));
}

#[test]
fn client_close_notify_ends_the_stream() {
    let config = server(&store());
    let (reads, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            tls.write_all(b"last").unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
            std::thread::sleep(Duration::from_millis(200));
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let mut buf = BytesMut::new();
            let mut reads = Vec::new();
            for _ in 0..3 {
                reads.push(io.read(&mut buf).await.map_err(|e| e.kind()));
            }
            (reads, buf)
        },
    );
    assert_eq!(reads.1, b"last"[..]);
    assert_eq!(reads.0, [Ok(4), Ok(0), Ok(0)]);
}

/// One exchange, so the client has read the session ticket: a socket closed with unread bytes
/// sends RST, not FIN.
fn round_trip(tls: &mut StreamOwned<ClientConnection, TcpStream>) {
    tls.write_all(b"?").unwrap();
    tls.read_exact(&mut [0u8; 1]).unwrap();
}

async fn echo_once(io: &mut Transport) {
    let got = read_exactly(io, 1).await;
    io.write_all_vectored(&mut [IoSlice::new(&got)])
        .await
        .unwrap();
}

#[test]
fn abrupt_close_between_records_is_end_of_stream() {
    let config = server(&store());
    let (read, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            round_trip(&mut tls);
            tls.write_all(b"req").unwrap();
            drop(tls);
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            echo_once(&mut io).await;
            let mut buf = BytesMut::new();
            let first = io.read(&mut buf).await.map_err(|e| e.kind());
            let second = io.read(&mut buf).await.map_err(|e| e.kind());
            (first, second)
        },
    );
    assert_eq!(read, (Ok(3), Ok(0)));
}

#[test]
fn abrupt_close_inside_a_record_is_an_error() {
    let config = server(&store());
    let (read, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            round_trip(&mut tls);
            let record = sealed_record(&mut tls, b"truncated");
            tls.sock.write_all(&record[..record.len() - 4]).unwrap();
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            echo_once(&mut io).await;
            io.read(&mut BytesMut::new()).await.map_err(|e| e.kind())
        },
    );
    assert_eq!(read, Err(io::ErrorKind::UnexpectedEof));
}

#[test]
fn tampered_record_is_an_error() {
    let config = server(&store());
    let (read, ()) = run(
        |addr| {
            let mut tls = Client::new(&[]).connect(addr, "a.test");
            let mut record = sealed_record(&mut tls, b"payload");
            record[8] ^= 1;
            tls.sock.write_all(&record).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            io.read(&mut BytesMut::new()).await.map_err(|e| e.kind())
        },
    );
    assert_eq!(read, Err(io::ErrorKind::InvalidData));
}

#[test]
fn handshake_timeout_closes_a_silent_client() {
    for hello_prefix in [&b""[..], &[22, 3, 1, 0, 200, 1][..]] {
        let config = server(&store());
        let (served, eof_after) = run(
            move |addr| {
                let mut tcp = TcpStream::connect(addr).unwrap();
                tcp.write_all(hello_prefix).unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let start = Instant::now();
                let n = tcp.read(&mut [0u8; 16]).unwrap();
                (n, start.elapsed())
            },
            async |sock| {
                let start = Instant::now();
                let result = accept_within(sock, config, Duration::from_millis(300)).await;
                (result.err(), start.elapsed())
            },
        );
        assert!(
            matches!(served.0, Some(TlsError::Timeout)),
            "{:?}",
            served.0
        );
        assert!(served.1 >= Duration::from_millis(300));
        assert_eq!(eof_after.0, 0, "the client sees the connection closed");
        assert!(eof_after.1 < Duration::from_secs(2));
    }
}

#[test]
fn ticket_issued_on_one_core_resumes_on_another() {
    let store = store();
    let keys = Arc::new(TicketKeys::generate(3600));
    for suite in [
        suites::TLS13_AES_128_GCM_SHA256,
        suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ] {
        let client = Arc::new(Client::with(&[], Some(suite)));
        let mut kinds = Vec::new();
        for core in 0..2 {
            let config = server_config(store.clone(), keys.clone());
            let client = client.clone();
            let ((), kind) = run(
                move |addr| {
                    let mut tls = client.connect(addr, "a.test");
                    tls.write_all(b"x").unwrap();
                    // TLS 1.3 tickets arrive after the handshake: read up to the close.
                    let mut rest = Vec::new();
                    tls.read_to_end(&mut rest).unwrap();
                    tls.conn.handshake_kind()
                },
                async |sock| {
                    let (mut io, _) = accepted(sock, config).await;
                    read_exactly(&mut io, 1).await;
                    io.close().await;
                },
            );
            kinds.push((core, kind));
        }
        assert_eq!(
            kinds,
            [
                (0, Some(HandshakeKind::Full)),
                (1, Some(HandshakeKind::Resumed))
            ],
            "{:?}",
            suite.suite()
        );
    }
}

#[test]
fn client_key_update_rotates_both_directions() {
    // TLS 1.3 records of 5 plaintext bytes, a 5-byte KeyUpdate or 5 bytes of data: header 5 +
    // 5 + content type 1 + tag 16.
    const RECORD: usize = 27;
    let config = server(&store());
    let ((), rounds) = run(
        |addr| {
            let tls = Client::new(&[]).connect(addr, "a.test");
            let read = Arc::new(AtomicUsize::new(0));
            let counting = Counting {
                tcp: tls.sock,
                read: read.clone(),
            };
            let mut tls = StreamOwned::new(tls.conn, counting);
            let mut rounds = Vec::new();
            for round in 0..3u8 {
                if round > 0 {
                    // rustls asks the peer to update too (update_requested).
                    tls.conn.refresh_traffic_keys().unwrap();
                }
                read.store(0, Ordering::Relaxed);
                tls.write_all(&[b'0' + round; 5]).unwrap();
                let mut reply = [0u8; 5];
                tls.read_exact(&mut reply).unwrap();
                rounds.push((reply, read.load(Ordering::Relaxed)));
            }
            rounds
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let mut buf = BytesMut::new();
            for _ in 0..3 {
                while buf.len() < 5 {
                    assert!(io.read(&mut buf).await.unwrap() > 0);
                }
                let req = buf.split_to(5);
                io.write_all_vectored(&mut [IoSlice::new(&req)])
                    .await
                    .unwrap();
            }
        },
    );
    let replies: Vec<_> = rounds.iter().map(|r| r.0).collect();
    assert_eq!(replies, [*b"00000", *b"11111", *b"22222"]);
    assert_eq!(
        [rounds[1].1, rounds[2].1],
        [2 * RECORD; 2],
        "each requested update is answered with our KeyUpdate before the reply"
    );
}

#[test]
fn echoed_requests_allocate_nothing_after_warm_up() {
    const WARM: usize = 20;
    const MEASURED: usize = 200;
    const REQUEST: &[u8] = b"GET /some/path HTTP/1.1\r\nHost: a.test\r\nUser-Agent: test\r\n\r\n";
    let config = server(&store());
    let (allocations, ()) = run(
        |addr| {
            let mut tls = Client::new(&[b"http/1.1"]).connect(addr, "a.test");
            let mut reply = [0u8; REQUEST.len()];
            for _ in 0..WARM + MEASURED {
                tls.write_all(REQUEST).unwrap();
                tls.read_exact(&mut reply).unwrap();
                assert_eq!(&reply[..], REQUEST);
            }
        },
        async |sock| {
            let (mut io, _) = accepted(sock, config).await;
            let mut buf = BytesMut::with_capacity(16 * 1024);
            let mut before = 0;
            for i in 0..WARM + MEASURED {
                if i == WARM {
                    before = crate::runtime::testing::thread_allocations();
                }
                io.readable().await.unwrap();
                while buf.len() < REQUEST.len() {
                    assert!(io.read(&mut buf).await.unwrap() > 0);
                }
                io.write_all_vectored(&mut [IoSlice::new(&buf)])
                    .await
                    .unwrap();
                buf.clear();
            }
            crate::runtime::testing::thread_allocations() - before
        },
    );
    assert_eq!(allocations, 0, "allocations for {MEASURED} echoed requests");
}

/// Serves one TLS connection with a fixed HTTP/1.1 response to whatever request head arrives;
/// returns the negotiated protocol.
fn serve_http(addr_tx: std::sync::mpsc::Sender<SocketAddr>) -> std::thread::JoinHandle<Proto> {
    let config = server(&store());
    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        addr_tx.send(listener.local_addr().unwrap()).unwrap();
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_nonblocking(true).unwrap();
        runtime().block_on(async move {
            let sock = Socket::from_fd(tcp.into()).unwrap();
            let (mut io, proto) = accepted(sock, config).await;
            let mut buf = BytesMut::new();
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                if io.read(&mut buf).await.unwrap() == 0 {
                    return proto;
                }
            }
            let body = b"hello over tls\n";
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            io.write_all_vectored(&mut [IoSlice::new(head.as_bytes()), IoSlice::new(body)])
                .await
                .unwrap();
            io.close().await;
            proto
        })
    })
}

fn tool(name: &str) -> bool {
    let found = std::process::Command::new(name)
        .arg("version")
        .output()
        .is_ok();
    if !found {
        eprintln!("{name} not installed: skipped");
    }
    found
}

#[test]
fn curl_fetches_over_http11() {
    if !tool("curl") {
        return;
    }
    for version in ["--tlsv1.3", "--tls-max"] {
        let (tx, rx) = std::sync::mpsc::channel();
        let served = serve_http(tx);
        let addr = rx.recv().unwrap();
        let mut cmd = std::process::Command::new("curl");
        cmd.args(["--silent", "--show-error", "--insecure", "--http1.1"]);
        if version == "--tls-max" {
            cmd.args(["--tls-max", "1.2"]);
        } else {
            cmd.arg(version);
        }
        let out = cmd
            .arg("--resolve")
            .arg(format!("www.example.test:{}:127.0.0.1", addr.port()))
            .arg(format!("https://www.example.test:{}/", addr.port()))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"hello over tls\n", "{version}");
        assert!(matches!(served.join().unwrap(), Proto::H1));
    }
}

#[test]
fn openssl_negotiates_h2_and_sni() {
    if !tool("openssl") {
        return;
    }
    for version in ["-tls1_3", "-tls1_2"] {
        let (tx, rx) = std::sync::mpsc::channel();
        let served = serve_http(tx);
        let addr = rx.recv().unwrap();
        let mut child = std::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &addr.to_string(),
                "-servername",
                "a.test",
            ])
            .args(["-alpn", "h2", version, "-ign_eof"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("ALPN protocol: h2"), "{version}: {stdout}");
        assert!(
            stdout.contains("subject=CN=a.test")
                || stdout.contains("CN = a.test")
                || stdout.contains("CN=a.test"),
            "{version}: {stdout}"
        );
        assert!(stdout.contains("hello over tls"), "{version}: {stdout}");
        assert!(matches!(served.join().unwrap(), Proto::H2));
    }
}
