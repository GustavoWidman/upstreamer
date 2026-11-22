//! The record layer of an established TLS connection, in the caller's buffers.
//!
//! rustls runs the handshake. `dangerous_into_kernel_connection` then hands over the traffic keys
//! and sequence numbers, the same hand-over kernel TLS uses, and records are sealed and opened in
//! place with aws-lc-rs. rustls copies every record into a `Vec` of its own on both paths; this
//! layer allocates nothing per record, and a write gathers any number of slices into full-size
//! records. rustls keeps the key schedule, so TLS 1.3 key updates work in both directions.
//!
//! Record formats: RFC 8446 5.2 (TLS 1.3), RFC 5288 (TLS 1.2 AES-GCM), RFC 7905 (TLS 1.2
//! ChaCha20-Poly1305).

use aws_lc_rs::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey,
};
use bytes::{BufMut, BytesMut};
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{
    AlertDescription, ConnectionTrafficSecrets, Error, ExtractedSecrets, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, SupportedCipherSuite,
};
use std::io::IoSlice;
use std::ops::Range;

const HEADER: usize = 5;
const TAG: usize = 16;
const MAX_PLAINTEXT: usize = 1 << 14;
/// The largest record a peer may send (RFC 5246 6.2.3 allows TLS 1.2 2048 bytes of expansion;
/// TLS 1.3 allows 256, checked per record).
pub(crate) const MAX_RECORD: usize = HEADER + MAX_PLAINTEXT + 2048;

const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const KEY_UPDATE: u8 = 24;
const CLOSE_NOTIFY: u8 = 0;
const USER_CANCELED: u8 = 90;
const WARNING: u8 = 1;
const FATAL: u8 = 2;
/// Records in a row that carry no data (empty records, key updates, ignorable alerts) before
/// the peer counts as misbehaving, as rustls counts them during its own record processing.
const MAX_QUIET_RECORDS: u8 = 32;
const LEGACY_VERSION: [u8; 2] = [3, 3];

/// The length of the record at the front of `buf`, once all of it has arrived.
pub(crate) fn record_len(buf: &[u8]) -> Result<Option<usize>, Error> {
    let Some(header) = buf.get(..HEADER) else {
        return Ok(None);
    };
    let len = HEADER + usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > MAX_RECORD {
        return Err(Error::PeerSentOversizedRecord);
    }
    Ok((buf.len() >= len).then_some(len))
}

/// How records of the negotiated version and cipher are laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// Outer type application_data; the real type is the last non-zero plaintext byte; the
    /// header is the additional data.
    Tls13,
    /// An 8-byte explicit nonce after the header; additional data is seq, type, version, length.
    Tls12Gcm,
    /// No explicit nonce; additional data as for GCM.
    Tls12ChaCha,
}

impl Framing {
    /// Bytes one record adds to its plaintext.
    fn overhead(self) -> usize {
        self.prefix() + self.suffix()
    }
    /// Bytes before the plaintext: the header, and TLS 1.2 GCM's explicit nonce.
    fn prefix(self) -> usize {
        match self {
            Framing::Tls12Gcm => HEADER + 8,
            Framing::Tls13 | Framing::Tls12ChaCha => HEADER,
        }
    }
    /// Bytes after the plaintext: TLS 1.3's content type, and the tag.
    fn suffix(self) -> usize {
        match self {
            Framing::Tls13 => 1 + TAG,
            Framing::Tls12Gcm | Framing::Tls12ChaCha => TAG,
        }
    }
}

/// One direction's AEAD key, IV and record sequence number.
struct Keys {
    aead: LessSafeKey,
    iv: [u8; NONCE_LEN],
    seq: u64,
}

impl Keys {
    fn new((seq, secrets): (u64, ConnectionTrafficSecrets)) -> Result<Keys, Error> {
        let (algorithm, key, iv) = match &secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (&AES_128_GCM, key, iv),
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (&AES_256_GCM, key, iv),
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (&CHACHA20_POLY1305, key, iv),
            _ => {
                return Err(Error::General(
                    "cipher without a userspace record layer".into(),
                ));
            }
        };
        let unbound = UnboundKey::new(algorithm, key.as_ref()).map_err(|_| Error::EncryptError)?;
        Ok(Keys {
            aead: LessSafeKey::new(unbound),
            iv: iv.as_ref().try_into().map_err(|_| Error::EncryptError)?,
            seq,
        })
    }

    /// IV XOR the sequence number: the TLS 1.3 and ChaCha nonce, and for TLS 1.2 GCM the salt
    /// followed by the explicit nonce rustls would send.
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        for (b, s) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(self.seq.to_be_bytes())
        {
            *b ^= s;
        }
        nonce
    }
}

fn tls12_aad(seq: u64, typ: u8, len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = typ;
    aad[9..11].copy_from_slice(&LEGACY_VERSION);
    aad[11..].copy_from_slice(&(len as u16).to_be_bytes());
    aad
}

/// What one opened record carried.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Opened {
    /// Application data, at this range of the record's bytes.
    Data(Range<usize>),
    /// Nothing for the caller: an empty record, a key update, an ignorable alert.
    Nothing,
    /// The peer's close_notify: no more data follows.
    Closed,
}

/// Both directions of an established connection.
pub(crate) struct Session {
    framing: Framing,
    seal: Keys,
    open: Keys,
    /// rustls's key schedule, for TLS 1.3 key updates.
    kernel: KernelConnection<ServerConnectionData>,
    /// Records the sealing key may protect (the suite's confidentiality limit).
    seal_limit: u64,
    /// TLS 1.3: our key update goes out before our next record (the peer asked for one, or the
    /// sealing key reached its limit).
    owe_key_update: bool,
    /// Records opened in a row that carried no data.
    quiet: u8,
}

impl Session {
    pub fn new(
        secrets: ExtractedSecrets,
        kernel: KernelConnection<ServerConnectionData>,
    ) -> Result<Session, Error> {
        let framing = match (kernel.protocol_version(), &secrets.tx.1) {
            (ProtocolVersion::TLSv1_3, _) => Framing::Tls13,
            (ProtocolVersion::TLSv1_2, ConnectionTrafficSecrets::Chacha20Poly1305 { .. }) => {
                Framing::Tls12ChaCha
            }
            (ProtocolVersion::TLSv1_2, _) => Framing::Tls12Gcm,
            _ => return Err(Error::HandshakeNotComplete),
        };
        let seal_limit = match kernel.negotiated_cipher_suite() {
            SupportedCipherSuite::Tls13(suite) => suite.common.confidentiality_limit,
            SupportedCipherSuite::Tls12(suite) => suite.common.confidentiality_limit,
        };
        Ok(Session {
            framing,
            seal: Keys::new(secrets.tx)?,
            open: Keys::new(secrets.rx)?,
            kernel,
            seal_limit,
            owe_key_update: false,
            quiet: 0,
        })
    }

    /// Opens the complete record `record` (header included, as measured by [`record_len`]) in
    /// place.
    pub fn open(&mut self, record: &mut [u8]) -> Result<Opened, Error> {
        let (header, body) = record.split_at_mut(HEADER);
        let header: [u8; HEADER] = (&*header).try_into().expect("split at HEADER");
        let outer = header[0];
        let keys = &self.open;
        let (typ, content) = match self.framing {
            Framing::Tls13 => {
                if outer != APPLICATION_DATA {
                    return Err(unexpected("unprotected record after the handshake"));
                }
                if body.len() > MAX_PLAINTEXT + 256 {
                    return Err(Error::PeerSentOversizedRecord);
                }
                let nonce = Nonce::assume_unique_for_key(keys.nonce());
                let inner = keys
                    .aead
                    .open_in_place(nonce, Aad::from(header), body)
                    .map_err(|_| Error::DecryptError)?;
                // TLSInnerPlaintext: content, type and padding together (RFC 8446 5.4).
                if inner.len() > MAX_PLAINTEXT + 1 {
                    return Err(Error::PeerSentOversizedRecord);
                }
                let end = inner
                    .iter()
                    .rposition(|&b| b != 0)
                    .ok_or(Error::InvalidMessage(InvalidMessage::InvalidContentType))?;
                (inner[end], HEADER..HEADER + end)
            }
            Framing::Tls12Gcm => {
                if body.len() < 8 + TAG {
                    return Err(Error::DecryptError);
                }
                let mut nonce = keys.iv;
                nonce[4..].copy_from_slice(&body[..8]);
                let aad = tls12_aad(keys.seq, outer, body.len() - 8 - TAG);
                let plain = keys
                    .aead
                    .open_in_place(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad),
                        &mut body[8..],
                    )
                    .map_err(|_| Error::DecryptError)?;
                (outer, HEADER + 8..HEADER + 8 + plain.len())
            }
            Framing::Tls12ChaCha => {
                if body.len() < TAG {
                    return Err(Error::DecryptError);
                }
                let aad = tls12_aad(keys.seq, outer, body.len() - TAG);
                let nonce = Nonce::assume_unique_for_key(keys.nonce());
                let plain = keys
                    .aead
                    .open_in_place(nonce, Aad::from(aad), body)
                    .map_err(|_| Error::DecryptError)?;
                (outer, HEADER..HEADER + plain.len())
            }
        };
        if content.len() > MAX_PLAINTEXT {
            return Err(Error::PeerSentOversizedRecord);
        }
        self.open.seq += 1;
        let opened = match typ {
            APPLICATION_DATA if content.is_empty() => Opened::Nothing,
            APPLICATION_DATA => Opened::Data(content),
            ALERT => self.alert(&record[content])?,
            HANDSHAKE => self.post_handshake(&record[content])?,
            _ => return Err(Error::InvalidMessage(InvalidMessage::InvalidContentType)),
        };
        if opened == Opened::Nothing {
            self.quiet += 1;
            if self.quiet > MAX_QUIET_RECORDS {
                return Err(Error::PeerMisbehaved(PeerMisbehaved::TooManyEmptyFragments));
            }
        } else {
            self.quiet = 0;
        }
        Ok(opened)
    }

    fn alert(&self, alert: &[u8]) -> Result<Opened, Error> {
        let &[level, description] = alert else {
            return Err(Error::InvalidMessage(InvalidMessage::MessageTooShort));
        };
        match description {
            CLOSE_NOTIFY => Ok(Opened::Closed),
            USER_CANCELED => Ok(Opened::Nothing),
            // TLS 1.2 warnings are not fatal; TLS 1.3 makes every other alert fatal.
            _ if level == WARNING && self.framing != Framing::Tls13 => Ok(Opened::Nothing),
            _ => Err(Error::AlertReceived(AlertDescription::from(description))),
        }
    }

    /// A client may send only a KeyUpdate after the TLS 1.3 handshake (no renegotiation in
    /// TLS 1.2). The record must hold exactly that message: keys change right after it.
    fn post_handshake(&mut self, message: &[u8]) -> Result<Opened, Error> {
        let &[KEY_UPDATE, 0, 0, 1, request] = message else {
            return Err(unexpected("handshake message after the handshake"));
        };
        if self.framing != Framing::Tls13 || request > 1 {
            return Err(Error::InvalidMessage(InvalidMessage::InvalidKeyUpdate));
        }
        self.open = Keys::new(self.kernel.update_rx_secret()?)?;
        if request == 1 {
            self.owe_key_update = true;
        }
        Ok(Opened::Nothing)
    }

    /// Seals the plaintext of `bufs`, starting `skip` bytes in, into records appended to `tx`,
    /// as long as the next record fits in `tx`'s capacity. Full-size records except the last.
    /// Returns the plaintext bytes sealed, at least one record's worth when `tx` starts empty.
    pub fn seal(
        &mut self,
        tx: &mut BytesMut,
        bufs: &[IoSlice<'_>],
        skip: usize,
    ) -> Result<usize, Error> {
        let left = bufs.iter().map(|b| b.len()).sum::<usize>() - skip;
        let mut sealed = 0;
        while sealed < left {
            let n = (left - sealed).min(MAX_PLAINTEXT);
            let key_update = self.key_update_due()?;
            let need = n + self.framing.overhead() + key_update * (5 + self.framing.overhead());
            if tx.capacity() - tx.len() < need {
                break;
            }
            if key_update == 1 {
                self.seal_record(tx, HANDSHAKE, 5, |tx| {
                    tx.extend_from_slice(&[KEY_UPDATE, 0, 0, 1, 0])
                })?;
                self.seal = Keys::new(self.kernel.update_tx_secret()?)?;
                self.owe_key_update = false;
            }
            self.seal_record(tx, APPLICATION_DATA, n, |tx| {
                gather(bufs, skip + sealed, n, tx)
            })?;
            sealed += n;
        }
        Ok(sealed)
    }

    /// Starts an application-data record at the end of `tx`, after the key update it must
    /// follow when one is due. [`Session::fill`] adds its plaintext and [`Session::finish`]
    /// seals it; nothing else may be sealed into `tx` meanwhile. Returns the record's offset,
    /// or `None` when `tx` has no room for its overhead and one byte of plaintext.
    pub fn begin(&mut self, tx: &mut BytesMut) -> Result<Option<usize>, Error> {
        let key_update = self.key_update_due()?;
        let need = 1 + self.framing.overhead() + key_update * (5 + self.framing.overhead());
        if tx.capacity() - tx.len() < need {
            return Ok(None);
        }
        if key_update == 1 {
            self.seal_record(tx, HANDSHAKE, 5, |tx| {
                tx.extend_from_slice(&[KEY_UPDATE, 0, 0, 1, 0])
            })?;
            self.seal = Keys::new(self.kernel.update_tx_secret()?)?;
            self.owe_key_update = false;
        }
        Ok(Some(self.start(tx)))
    }

    /// Appends as much of `bufs` to the record begun at `start` as both the record and `tx`'s
    /// capacity hold. Returns the bytes taken, and whether the record is full.
    pub fn fill(&self, tx: &mut BytesMut, start: usize, bufs: &[IoSlice<'_>]) -> (usize, bool) {
        let used = tx.len() - start - self.framing.prefix();
        let room = (MAX_PLAINTEXT - used).min(tx.capacity() - tx.len() - self.framing.suffix());
        let n = room.min(bufs.iter().map(|b| b.len()).sum());
        gather(bufs, 0, n, tx);
        (n, n == room)
    }

    /// Seals the record begun at `start`.
    pub fn finish(&mut self, tx: &mut BytesMut, start: usize) -> Result<(), Error> {
        self.seal_started(tx, start, APPLICATION_DATA)
    }

    /// 1 when a key update must precede the next record: the update itself is the last record
    /// the old key protects. TLS 1.2 has no key update, so its connection ends one record short
    /// of the limit, which leaves room for close_notify.
    fn key_update_due(&mut self) -> Result<usize, Error> {
        if self.seal.seq + 1 >= self.seal_limit {
            if self.framing != Framing::Tls13 {
                return Err(Error::EncryptError);
            }
            self.owe_key_update = true;
        }
        Ok(usize::from(self.owe_key_update))
    }

    /// Appends a close_notify alert to `tx`.
    pub fn seal_close_notify(&mut self, tx: &mut BytesMut) -> Result<(), Error> {
        self.seal_record(tx, ALERT, 2, |tx| {
            tx.extend_from_slice(&[WARNING, CLOSE_NOTIFY])
        })
    }

    /// Appends the fatal alert that answers `error` from [`Session::open`] (RFC 8446 6.2), if
    /// it has one: none for an alert the peer sent, after which it is gone. True if appended.
    pub fn seal_fatal_alert(&mut self, tx: &mut BytesMut, error: &Error) -> bool {
        let description = match error {
            Error::AlertReceived(_) => return false,
            Error::DecryptError => AlertDescription::BadRecordMac,
            Error::PeerSentOversizedRecord => AlertDescription::RecordOverflow,
            Error::InvalidMessage(InvalidMessage::InvalidKeyUpdate) => {
                AlertDescription::IllegalParameter
            }
            Error::InvalidMessage(InvalidMessage::MessageTooShort) => AlertDescription::DecodeError,
            _ => AlertDescription::UnexpectedMessage,
        };
        self.seal_record(tx, ALERT, 2, |tx| {
            tx.extend_from_slice(&[FATAL, u8::from(description)])
        })
        .is_ok()
    }

    /// Appends one record of type `typ` whose `n` plaintext bytes `fill` appends.
    fn seal_record(
        &mut self,
        tx: &mut BytesMut,
        typ: u8,
        n: usize,
        fill: impl FnOnce(&mut BytesMut),
    ) -> Result<(), Error> {
        let start = self.start(tx);
        fill(tx);
        debug_assert_eq!(tx.len() - start - self.framing.prefix(), n);
        self.seal_started(tx, start, typ)
    }

    /// Appends what precedes a record's plaintext: room for the header and, for TLS 1.2 GCM,
    /// the explicit nonce. Returns the record's offset.
    fn start(&self, tx: &mut BytesMut) -> usize {
        let start = tx.len();
        tx.extend_from_slice(&[0; HEADER]);
        if self.framing == Framing::Tls12Gcm {
            tx.extend_from_slice(&self.seal.nonce()[4..]);
        }
        start
    }

    /// Seals the record of type `typ` at `start`, whose plaintext runs to the end of `tx`.
    fn seal_started(&mut self, tx: &mut BytesMut, start: usize, typ: u8) -> Result<(), Error> {
        let from = start + self.framing.prefix();
        let n = tx.len() - from;
        let keys = &mut self.seal;
        let nonce = keys.nonce();
        let len = n + self.framing.overhead() - HEADER;
        let [len_hi, len_lo] = (len as u16).to_be_bytes();
        let outer = match self.framing {
            Framing::Tls13 => APPLICATION_DATA,
            Framing::Tls12Gcm | Framing::Tls12ChaCha => typ,
        };
        let header = [outer, LEGACY_VERSION[0], LEGACY_VERSION[1], len_hi, len_lo];
        tx[start..start + HEADER].copy_from_slice(&header);
        let mut aad = [0u8; 13];
        let aad_len = match self.framing {
            Framing::Tls13 => {
                tx.put_u8(typ);
                aad[..HEADER].copy_from_slice(&header);
                HEADER
            }
            Framing::Tls12Gcm | Framing::Tls12ChaCha => {
                aad = tls12_aad(keys.seq, typ, n);
                aad.len()
            }
        };
        let tag = keys
            .aead
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..aad_len]),
                &mut tx[from..],
            )
            .map_err(|_| Error::EncryptError)?;
        tx.extend_from_slice(tag.as_ref());
        debug_assert_eq!(tx.len() - start, HEADER + len);
        keys.seq += 1;
        Ok(())
    }
}

/// Appends `n` bytes of the concatenation of `bufs`, starting `skip` bytes in.
fn gather(bufs: &[IoSlice<'_>], mut skip: usize, mut n: usize, out: &mut BytesMut) {
    for buf in bufs {
        if n == 0 {
            break;
        }
        if skip >= buf.len() {
            skip -= buf.len();
            continue;
        }
        let take = (buf.len() - skip).min(n);
        out.extend_from_slice(&buf[skip..skip + take]);
        n -= take;
        skip = 0;
    }
}

fn unexpected(what: &'static str) -> Error {
    Error::InvalidMessage(InvalidMessage::UnexpectedMessage(what))
}

/// Fuzz entry points; not part of the API.
#[cfg(feature = "internals")]
pub mod harness {
    use super::*;
    use aws_lc_rs::aead::Algorithm;
    use rustls::client::ClientConnection;
    use rustls::crypto::CryptoProvider;
    use rustls::server::{ClientHello, ResolvesServerCert, UnbufferedServerConnection};
    use rustls::sign::CertifiedKey;
    use rustls::unbuffered::{ConnectionState, EncodeError};
    use std::cell::RefCell;
    use std::sync::Arc;

    /// A connection's server half after the handshake, and what its client seals with.
    struct Connection {
        session: Session,
        /// The client's sending key, IV and first sequence number: the server's opening ones.
        client: (&'static Algorithm, Vec<u8>, [u8; NONCE_LEN], u64),
    }

    impl Connection {
        fn keys(&self) -> Keys {
            let (algorithm, key, iv, seq) = &self.client;
            Keys {
                aead: LessSafeKey::new(UnboundKey::new(algorithm, key).unwrap()),
                iv: *iv,
                seq: *seq,
            }
        }
    }

    #[derive(Debug)]
    struct One(Arc<CertifiedKey>);

    impl ResolvesServerCert for One {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// A handshake between a rustls client and the unbuffered server the proxy runs, in
    /// memory, with one cipher suite.
    fn connect(suite: SupportedCipherSuite) -> Connection {
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![suite],
            ..rustls::crypto::aws_lc_rs::default_provider()
        });
        let version = suite.version();
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(One(crate::tls::self_signed("fuzz.test").unwrap())));
        server.enable_secret_extraction = true;
        server.send_tls13_tickets = 0;
        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::AcceptAnyCert { provider }))
            .with_no_client_auth();
        client.enable_secret_extraction = true;
        let mut client =
            ClientConnection::new(Arc::new(client), "fuzz.test".try_into().unwrap()).unwrap();
        let mut server = UnbufferedServerConnection::new(Arc::new(server)).unwrap();
        let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
        loop {
            while client.wants_write() {
                client.write_tls(&mut to_server).unwrap();
            }
            let mut done = false;
            loop {
                let status = server.process_tls_records(&mut to_server);
                let discard = status.discard;
                let more = match status.state.unwrap() {
                    ConnectionState::EncodeTlsData(mut data) => {
                        let start = to_client.len();
                        to_client.resize(start + 16 * 1024, 0);
                        let n = match data.encode(&mut to_client[start..]) {
                            Ok(n) => n,
                            Err(EncodeError::InsufficientSize(e)) => panic!("{e:?}"),
                            Err(e) => panic!("{e:?}"),
                        };
                        to_client.truncate(start + n);
                        true
                    }
                    ConnectionState::TransmitTlsData(data) => {
                        data.done();
                        true
                    }
                    ConnectionState::BlockedHandshake => false,
                    ConnectionState::WriteTraffic(_) => {
                        done = true;
                        false
                    }
                    _ => panic!("unexpected handshake state"),
                };
                to_server.drain(..discard);
                if !more {
                    break;
                }
            }
            let mut from_server = &to_client[..];
            while !from_server.is_empty() {
                client.read_tls(&mut from_server).unwrap();
            }
            to_client.clear();
            client.process_new_packets().unwrap();
            if done && !server.is_handshaking() && !client.is_handshaking() {
                break;
            }
        }
        let (secrets, kernel) = server.dangerous_into_kernel_connection().unwrap();
        let session = Session::new(secrets, kernel).unwrap();
        let (seq, secrets) = client.dangerous_extract_secrets().unwrap().tx;
        let (algorithm, key, iv) = match &secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (&AES_128_GCM, key, iv),
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (&AES_256_GCM, key, iv),
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (&CHACHA20_POLY1305, key, iv),
            _ => unreachable!("an AEAD suite"),
        };
        Connection {
            session,
            client: (
                algorithm,
                key.as_ref().to_vec(),
                iv.as_ref().try_into().unwrap(),
                seq,
            ),
        }
    }

    thread_local! {
        static CONNECTIONS: RefCell<Vec<Connection>> = RefCell::new({
            use rustls::crypto::aws_lc_rs::cipher_suite::*;
            [
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
            .into_iter()
            .map(connect)
            .collect()
        });
    }

    /// Seals one record as the client would: `typ` and `plain`, and for TLS 1.3 `pad` zero
    /// bytes of padding after the content type.
    fn seal(framing: Framing, keys: &mut Keys, typ: u8, plain: &[u8], pad: usize) -> Vec<u8> {
        let nonce = keys.nonce();
        let (outer, mut body, aad) = match framing {
            Framing::Tls13 => {
                let mut inner = plain.to_vec();
                inner.push(typ);
                inner.resize(inner.len() + pad, 0);
                (APPLICATION_DATA, inner, None)
            }
            _ => (
                typ,
                plain.to_vec(),
                Some(tls12_aad(keys.seq, typ, plain.len())),
            ),
        };
        let explicit = match framing {
            Framing::Tls12Gcm => nonce[4..].to_vec(),
            _ => Vec::new(),
        };
        let len = (explicit.len() + body.len() + TAG) as u16;
        let header = [
            outer,
            LEGACY_VERSION[0],
            LEGACY_VERSION[1],
            (len >> 8) as u8,
            len as u8,
        ];
        let tag = match aad {
            None => keys.aead.seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(header),
                &mut body,
            ),
            Some(aad) => keys.aead.seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut body,
            ),
        }
        .unwrap();
        keys.seq += 1;
        let mut record = header.to_vec();
        record.extend_from_slice(&explicit);
        record.extend_from_slice(&body);
        record.extend_from_slice(tag.as_ref());
        record
    }

    /// A client's bytes after the handshake, opened as the connection's transport opens
    /// them. The first byte picks the cipher suite (TLS 1.3 AES-128-GCM, AES-256-GCM or
    /// ChaCha20-Poly1305, TLS 1.2 AES-128-GCM or ChaCha20-Poly1305). Then steps, each a
    /// kind byte, a length byte and that many bytes: raw bytes (kind 0 mod 4); a sealed
    /// record of application data (1); a sealed record whose first byte is its content
    /// type (2); or a sealed record with one byte changed (3). The kind's upper bits add that
    /// many 64-byte runs to the bytes and, for TLS 1.3, as many bytes of padding.
    ///
    /// Whatever the bytes are, the record layer opens only the records the client sealed,
    /// unchanged, and the application data of each is the bytes sealed in it.
    pub fn input(data: &[u8]) {
        let Some((&suite, mut steps)) = data.split_first() else {
            return;
        };
        CONNECTIONS.with_borrow_mut(|connections| {
            let count = connections.len();
            let connection = &mut connections[usize::from(suite) % count];
            let framing = connection.session.framing;
            let mut client = connection.keys();
            connection.session.open = connection.keys();
            connection.session.quiet = 0;
            connection.session.owe_key_update = false;

            let mut stream = Vec::new();
            // The records the client sealed and left alone: where each starts, its length,
            // its content type and its plaintext.
            let mut sealed = Vec::new();
            while let [kind, len, rest @ ..] = steps {
                let len = usize::from(*len).min(rest.len());
                let (bytes, tail) = rest.split_at(len);
                steps = tail;
                let runs = usize::from(kind >> 2);
                let mut bytes = bytes.to_vec();
                bytes.resize(bytes.len() + runs * 64, b'r');
                let bytes = &bytes[..bytes.len().min(MAX_PLAINTEXT + 64)];
                let pad = runs * 64;
                match kind & 3 {
                    0 => stream.extend_from_slice(bytes),
                    1 | 2 => {
                        let (typ, plain) = match kind & 3 {
                            1 => (APPLICATION_DATA, bytes),
                            _ => bytes
                                .split_first()
                                .map_or((APPLICATION_DATA, &[][..]), |(&t, p)| (t, p)),
                        };
                        let record = seal(framing, &mut client, typ, plain, pad);
                        // TLS 1.3's content type is the last byte of the inner plaintext that
                        // is not zero: a type of 0 is padding, and what precedes it decides.
                        let expected = match framing {
                            Framing::Tls13 if typ == 0 => plain
                                .iter()
                                .rposition(|&b| b != 0)
                                .map(|end| (plain[end], &plain[..end])),
                            _ => Some((typ, plain)),
                        };
                        if let Some((typ, plain)) = expected {
                            sealed.push((stream.len(), record.len(), typ, plain.to_vec()));
                        }
                        stream.extend_from_slice(&record);
                    }
                    _ => {
                        let mut record = seal(framing, &mut client, APPLICATION_DATA, bytes, 0);
                        let at = (runs * 7 + bytes.len()) % record.len();
                        record[at] ^= 1 + (kind >> 4);
                        stream.extend_from_slice(&record);
                    }
                }
            }

            let session = &mut connection.session;
            let mut at = 0;
            while let Ok(Some(len)) = record_len(&stream[at..]) {
                assert!(len <= MAX_RECORD);
                let record = &mut stream[at..at + len];
                let opened = session.open(record);
                if let Ok(opened) = &opened {
                    let Some((_, _, typ, plain)) = sealed.iter().find(|s| (s.0, s.1) == (at, len))
                    else {
                        panic!("a record the client did not seal opened: {opened:?}");
                    };
                    match opened {
                        Opened::Data(range) => {
                            assert_eq!(*typ, APPLICATION_DATA);
                            assert_eq!(&record[range.clone()], &plain[..]);
                        }
                        Opened::Nothing if *typ == APPLICATION_DATA => assert!(plain.is_empty()),
                        Opened::Nothing | Opened::Closed => assert_ne!(*typ, APPLICATION_DATA),
                    }
                }
                match opened {
                    Ok(Opened::Data(_) | Opened::Nothing) => at += len,
                    Ok(Opened::Closed) | Err(_) => break,
                }
            }
        });
    }
}
