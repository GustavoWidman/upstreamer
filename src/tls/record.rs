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
    ProtocolVersion, SupportedCipherSuite,
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
        match self {
            Framing::Tls13 => HEADER + 1 + TAG,
            Framing::Tls12Gcm => HEADER + 8 + TAG,
            Framing::Tls12ChaCha => HEADER + TAG,
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
        match typ {
            APPLICATION_DATA if content.is_empty() => Ok(Opened::Nothing),
            APPLICATION_DATA => Ok(Opened::Data(content)),
            ALERT => self.alert(&record[content]),
            HANDSHAKE => self.post_handshake(&record[content]),
            _ => Err(Error::InvalidMessage(InvalidMessage::InvalidContentType)),
        }
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

    /// 1 when a key update must precede the next record. TLS 1.2 has no key update, so a
    /// connection whose key reached its limit ends.
    fn key_update_due(&mut self) -> Result<usize, Error> {
        if self.seal.seq >= self.seal_limit {
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

    /// Appends one record of type `typ` whose `n` plaintext bytes `fill` appends.
    fn seal_record(
        &mut self,
        tx: &mut BytesMut,
        typ: u8,
        n: usize,
        fill: impl FnOnce(&mut BytesMut),
    ) -> Result<(), Error> {
        let start = tx.len();
        let keys = &mut self.seal;
        let nonce = keys.nonce();
        let len = n + self.framing.overhead() - HEADER;
        let [len_hi, len_lo] = (len as u16).to_be_bytes();
        let outer = match self.framing {
            Framing::Tls13 => APPLICATION_DATA,
            Framing::Tls12Gcm | Framing::Tls12ChaCha => typ,
        };
        let header = [outer, LEGACY_VERSION[0], LEGACY_VERSION[1], len_hi, len_lo];
        tx.extend_from_slice(&header);
        let mut aad = [0u8; 13];
        let (aad_len, from) = match self.framing {
            Framing::Tls13 => {
                fill(tx);
                tx.put_u8(typ);
                aad[..HEADER].copy_from_slice(&header);
                (HEADER, HEADER)
            }
            Framing::Tls12Gcm => {
                tx.extend_from_slice(&nonce[4..]);
                fill(tx);
                aad = tls12_aad(keys.seq, typ, n);
                (aad.len(), HEADER + 8)
            }
            Framing::Tls12ChaCha => {
                fill(tx);
                aad = tls12_aad(keys.seq, typ, n);
                (aad.len(), HEADER)
            }
        };
        let tag = keys
            .aead
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..aad_len]),
                &mut tx[start + from..],
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
