//! The account key and the JSON Web Signatures every ACME request carries (RFC 8555 section
//! 6.2): ES256 over P-256, flattened JSON serialization, the key as a JWK in the request that
//! creates the account and the account URL (`kid`) in every later one.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;

/// The ACME account's private key, with its public JWK and thumbprint computed once.
pub(super) struct AccountKey {
    pair: EcdsaKeyPair,
    /// The public key as RFC 7638 canonical JSON: members in lexicographic order, no spaces.
    jwk: String,
    /// base64url(SHA-256(jwk)), the account's half of every key authorization.
    thumbprint: String,
}

/// How a request names its signer.
pub(super) enum Signer<'a> {
    /// The public key itself: only `newAccount`, before there is an account URL.
    Jwk,
    /// The account URL the CA returned.
    Kid(&'a str),
}

impl AccountKey {
    /// A new P-256 key, and its PKCS#8 encoding for the state directory.
    pub fn generate() -> Result<(AccountKey, Vec<u8>), String> {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map_err(|_| "generating the account key failed".to_owned())?;
        let pkcs8 = pair
            .to_pkcs8v1()
            .map_err(|_| "encoding the account key failed".to_owned())?;
        let pkcs8 = pkcs8.as_ref().to_vec();
        Ok((AccountKey::new(pair), pkcs8))
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<AccountKey, String> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map(AccountKey::new)
            .map_err(|e| format!("not a PKCS#8 P-256 key: {e}"))
    }

    fn new(pair: EcdsaKeyPair) -> AccountKey {
        let jwk = jwk(pair.public_key().as_ref());
        let thumbprint = base64url(digest(&SHA256, jwk.as_bytes()).as_ref());
        AccountKey {
            pair,
            jwk,
            thumbprint,
        }
    }

    /// The JWS of `payload` (a JSON text, or empty for POST-as-GET) for a request to `url`.
    pub fn sign(&self, signer: Signer<'_>, nonce: &str, url: &str, payload: &str) -> Vec<u8> {
        let mut header = json!({ "alg": "ES256", "nonce": nonce, "url": url });
        match signer {
            Signer::Jwk => {
                header["jwk"] = serde_json::from_str(&self.jwk).expect("the JWK is JSON");
            }
            Signer::Kid(kid) => header["kid"] = kid.into(),
        }
        let protected = base64url(header.to_string().as_bytes());
        let payload = base64url(payload.as_bytes());
        let signing_input = format!("{protected}.{payload}");
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .expect("ECDSA signing does not fail");
        let signature = base64url(signature.as_ref());
        json!({ "protected": protected, "payload": payload, "signature": signature })
            .to_string()
            .into_bytes()
    }

    /// `token.thumbprint` (RFC 8555 section 8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint)
    }
}

/// The JWK of an uncompressed P-256 point (`04 || x || y`), canonical per RFC 7638 section 3.
fn jwk(point: &[u8]) -> String {
    let (x, y) = point[1..].split_at(32);
    format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        base64url(x),
        base64url(y)
    )
}

const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64url without padding (RFC 7515 section 2).
pub(super) fn base64url(bytes: &[u8]) -> String {
    base64(bytes, URL_SAFE, false)
}

/// Standard base64 with padding (RFC 4648 section 4), as PEM bodies use.
pub(super) fn base64_padded(bytes: &[u8]) -> String {
    base64(bytes, STANDARD, true)
}

fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let digits = chunk.len() + 1;
        for i in 0..4 {
            if i < digits {
                out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Whether `token` is a challenge token as RFC 8555 section 8.3 allows: base64url characters
/// only, at least 128 bits of entropy (22 characters).
pub(super) fn is_token(token: &str) -> bool {
    token.len() >= 22
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use serde_json::Value;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(base64_padded(plain.as_bytes()), encoded);
            assert_eq!(base64url(plain.as_bytes()), encoded.trim_end_matches('='));
        }
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64_padded(&[0xfb, 0xff]), "+/8=");
    }

    fn decode(text: &str) -> Vec<u8> {
        let value = |c: u8| URL_SAFE.iter().position(|&a| a == c).unwrap() as u32;
        let mut out = Vec::new();
        for chunk in text.as_bytes().chunks(4) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0, |n, (i, &c)| n | value(c) << (18 - 6 * i));
            out.extend_from_slice(&n.to_be_bytes()[1..chunk.len()]);
        }
        out
    }

    #[test]
    fn a_request_is_an_es256_jws_over_its_header_and_payload() {
        let (key, pkcs8) = AccountKey::generate().unwrap();
        let reloaded = AccountKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(reloaded.jwk, key.jwk, "the stored key is the same key");

        let jws: Value =
            serde_json::from_slice(&key.sign(Signer::Jwk, "n0nce", "https://ca/acct", "{}"))
                .unwrap();
        let protected = jws["protected"].as_str().unwrap();
        let payload = jws["payload"].as_str().unwrap();
        let header: Value = serde_json::from_slice(&decode(protected)).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "n0nce");
        assert_eq!(header["url"], "https://ca/acct");
        assert!(header.get("kid").is_none());
        assert_eq!(decode(payload), b"{}");

        let jwk = &header["jwk"];
        assert_eq!(
            (jwk["kty"].as_str(), jwk["crv"].as_str()),
            (Some("EC"), Some("P-256"))
        );
        let mut point = vec![4];
        point.extend(decode(jwk["x"].as_str().unwrap()));
        point.extend(decode(jwk["y"].as_str().unwrap()));
        let signature = decode(jws["signature"].as_str().unwrap());
        assert_eq!(
            signature.len(),
            64,
            "r || s, 32 bytes each (RFC 7518 section 3.4)"
        );
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(format!("{protected}.{payload}").as_bytes(), &signature)
            .expect("the signature verifies with the JWK's key");

        let jws: Value =
            serde_json::from_slice(&key.sign(Signer::Kid("https://ca/acct/1"), "n", "u", ""))
                .unwrap();
        let header: Value =
            serde_json::from_slice(&decode(jws["protected"].as_str().unwrap())).unwrap();
        assert_eq!(header["kid"], "https://ca/acct/1");
        assert!(header.get("jwk").is_none());
        assert_eq!(jws["payload"], "", "POST-as-GET has an empty payload");
    }

    /// A fixed P-256 key whose public point and RFC 7638 thumbprint were computed
    /// independently of this module (affine arithmetic on the curve, canonical JSON, SHA-256).
    #[test]
    fn the_key_authorization_is_the_token_and_the_jwk_thumbprint() {
        let x = "4v5JKFEhpBiUXqQDx7lbAYRpKnm_F_eyS8DBiICewLw";
        let y = "mBWFwyRffK-ioF247gpxusRS3-LuZ6h4NJ-uTqaV6FM";
        let d = decode("951rlhh9c-uJjbr5Lx9Yjnb_deonzLC3RFIqANmhh3Y");
        let mut point = vec![4];
        point.extend(decode(x));
        point.extend(decode(y));
        let pair = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &d,
            &point,
        )
        .unwrap();
        let key = AccountKey::new(pair);
        assert_eq!(
            key.jwk,
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
        );
        assert_eq!(
            key.key_authorization("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"),
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.d4RNI_6mLALpqpLw72FuBSu9RQ1ifBJuriW204u2cZg"
        );
    }

    #[test]
    fn tokens_are_base64url_with_enough_entropy() {
        assert!(is_token("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"));
        assert!(!is_token("short"));
        assert!(!is_token("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ/../etc/passwd"));
        assert!(!is_token("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ PCt92wr"));
    }
}
