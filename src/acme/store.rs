//! The state directory's files: account keys and issued pairs. Every file is written whole,
//! readable by the owner only, under a directory readable by the owner only, and replaced
//! with a rename, so a reader (a reload, a restart) sees the old file or the new one, never a
//! part of either.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

/// The file's contents; `None` when it does not exist.
pub(super) fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Replaces `path` with `bytes`, mode 0600, creating missing directories with mode 0700. A
/// temporary file a crash left behind is removed first, so the file is always created anew
/// with this mode.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("a file path without a directory"))?;
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("a path without a file name"))?;
    let temp = dir.join(format!(".{}.new", name.to_string_lossy()));
    match std::fs::remove_file(&temp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)?;
    File::open(dir)?.sync_all()
}

/// A PEM block (RFC 7468) of `der`, with 64-column lines.
pub(super) fn pem(label: &str, der: &[u8]) -> String {
    let body = super::jws::base64_padded(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn files_are_private_and_replaced_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme/ca/accounts/ops.key");
        assert_eq!(read(&path).unwrap(), None);

        write_private(&path, b"first").unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"first"[..]));
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&dir.path().join("acme")), 0o700);

        let stale = path.with_file_name(".ops.key.new");
        std::fs::write(&stale, b"left by a crash").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some(&b"second"[..]));
        assert_eq!(
            mode(&path),
            0o600,
            "a stale temporary file's mode is not inherited"
        );
        assert!(!stale.exists());
    }

    #[test]
    fn pem_blocks_parse_back() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let der = key.serialize_der();
        let text = pem("PRIVATE KEY", &der);
        assert!(text.lines().all(|l| l.len() <= 64));
        let parsed = PrivateKeyDer::from_pem_slice(text.as_bytes()).unwrap();
        assert_eq!(parsed.secret_der(), &der[..]);
    }
}
