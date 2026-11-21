//! Static files. Synchronous: everything it needs comes from the per-core [`Catalog`], which
//! for immutable roots (under /nix/store) holds metadata, ETags, sidecar variants, open file
//! descriptors and the bytes of small files, so a warm request does no file syscall at all
//! except sendfile/pread for large bodies.
//!
//! Behaviour:
//! - path = root + clean path; a directory serves its first `index` file; no directory
//!   listings, no canonical-URI redirects.
//! - The file server never serves its own sidecars (`<f>.br`, `.zst`, `.gz` for the listed
//!   encodings, `<f><etagSidecar>`, whenever `<f>` is a file): they 404 when requested
//!   directly. A `.gz` with no file beside it is an ordinary file.
//! - Only GET and HEAD (405 otherwise). HEAD gets the GET response's head and body; the
//!   driver sends the head only, with the body's length as Content-Length.
//! - Encoding: the client's Accept-Encoding (q-values honoured) intersected with
//!   `precompressed` in config order, if the sidecar exists. Otherwise the identity body,
//!   which the pipeline may compress dynamically for an `encode` set.
//!   `vary_accept_encoding` whenever a sidecar exists, so caches key on the header.
//! - Bodies: files up to 64 KiB come from memory as `Body::Bytes`, larger ones as
//!   `Body::File` on a descriptor the catalog keeps open.
//! - ETag: one per representation, as Caddy gives: the trimmed content of the ETag sidecar
//!   beside the file sent (`index.html.etag` for the identity bytes, `index.html.br.etag` for
//!   the brotli ones) when `etagSidecar` is set and it holds one valid entity-tag, else for
//!   /nix/store files a hash of the store path and size (store mtimes are all 1), else
//!   mtime+size. Conditionals compare against the tag of the representation the request gets.
//! - No Last-Modified for files whose mtime is <= 1 (every store path).
//! - If-None-Match (weak comparison) -> 304; If-Modified-Since only without If-None-Match.
//! - Range: one `bytes=` range -> 206 on the identity representation (a ranged request never
//!   gets a compressed variant), If-Range honoured; multi-range -> 200 full. Every 200 and 206,
//!   precompressed ones included, says `Accept-Ranges: bytes`.
//! - In an error route: served with the error's status, conditionals and ranges ignored, and
//!   without validators (an error page's ETag would let a cache revalidate the error).

pub(crate) mod catalog;
pub(crate) mod negotiate;

use crate::body::Body;
use crate::encode::Encoding;
use crate::exchange::{ASpan, Exchange};
use crate::msg::{Known, Method, Status};
use crate::pipeline::Response;
use crate::plan::FilesPlan;
use catalog::{Catalog, Content, Data, FileEntry, Node, Want};
use negotiate::{Conditional, RangeDecision};
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::rc::Rc;

/// A file body to send: an open descriptor shared with the catalog, and the byte range.
/// Files small enough to be cached in memory are answered as `Body::Bytes` instead.
pub(crate) struct FileBody {
    pub file: Rc<File>,
    pub range: Range<u64>,
}

/// The settings of one `files` action, apart from its root.
struct Options<'a> {
    precompressed: &'a [Encoding],
    etag_sidecar: Option<&'a [u8]>,
    index: &'a [Box<[u8]>],
}

/// Answers from the file system. `Err(404)` (or 405) goes through the error routes.
/// `root` is the expanded root template, in the exchange's arena.
pub(crate) fn serve(
    plan: &FilesPlan,
    root: ASpan,
    ex: &mut Exchange,
    catalog: &mut Catalog,
) -> Result<Response, Status> {
    let options = Options {
        precompressed: &plan.precompressed,
        etag_sidecar: plan.etag_sidecar.as_deref(),
        index: &plan.index,
    };
    serve_with(&options, root, ex, catalog)
}

fn serve_with(
    options: &Options<'_>,
    root: ASpan,
    ex: &mut Exchange,
    catalog: &mut Catalog,
) -> Result<Response, Status> {
    let error = ex.error.map(|e| e.status);
    let method = ex.req.method;
    if error.is_none() && !matches!(method, Method::Get | Method::Head) {
        return Err(Status::new(405).expect("405 is a status code"));
    }
    let file = find(
        options,
        ex.arena.get(root),
        ex.req.path().as_bytes(),
        catalog,
    )?;

    let fields = &ex.req.fields;
    let vary = options
        .precompressed
        .iter()
        .any(|&e| file.content(Some(e)).is_some());
    let negotiated = negotiate::pick_encoding(
        fields.get(Known::AcceptEncoding),
        options.precompressed,
        |e| file.content(Some(e)).is_some(),
    );

    let Some(status) = error else {
        let decision = match method {
            Method::Get => negotiate::range(
                fields.get(Known::Range),
                fields.get(Known::IfRange),
                Some(&file.identity.etag),
                file.identity.len,
            ),
            _ => RangeDecision::Full,
        };
        let encoding = match decision {
            RangeDecision::Full => negotiated,
            RangeDecision::Partial(_) | RangeDecision::NotSatisfiable => None,
        };
        let content = file.content(encoding).expect("negotiated variants exist");
        if let Conditional::NotModified = negotiate::conditional(
            fields.get(Known::IfNoneMatch),
            fields.get(Known::IfModifiedSince),
            Some(&content.etag),
            file.mtime,
        ) {
            let mut head = ex.response_head(Status::NOT_MODIFIED);
            head.fields.append_known(Known::ETag, &content.etag);
            head.vary_accept_encoding = vary;
            return Ok(local(head, Body::Empty));
        }
        let (status, range) = match decision {
            RangeDecision::Full => (Status::OK, 0..content.len),
            RangeDecision::Partial(range) => (Status::PARTIAL_CONTENT, range),
            RangeDecision::NotSatisfiable => {
                let mut head = ex.response_head(Status::RANGE_NOT_SATISFIABLE);
                let mut buf = [0u8; 32];
                head.fields.push(
                    b"content-range",
                    fmt(&mut buf, format_args!("bytes */{}", file.identity.len)),
                );
                return Ok(local(head, Body::Empty));
            }
        };
        let mut head = ex.response_head(status);
        head.fields
            .append_known(Known::ContentType, file.content_type.as_bytes());
        if let Some(encoding) = encoding {
            head.fields
                .append_known(Known::ContentEncoding, encoding.token());
        }
        head.fields.append_known(Known::ETag, &content.etag);
        if let Some(date) = &file.last_modified {
            head.fields.append_known(Known::LastModified, date);
        }
        head.fields.push(b"accept-ranges", b"bytes");
        if status == Status::PARTIAL_CONTENT {
            let mut buf = [0u8; 64];
            let value = fmt(
                &mut buf,
                format_args!("bytes {}-{}/{}", range.start, range.end - 1, content.len),
            );
            head.fields.push(b"content-range", value);
        }
        head.vary_accept_encoding = vary;
        return Ok(local(head, body(content, range)));
    };

    let encoding = negotiated;
    let content = file.content(encoding).expect("negotiated variants exist");
    let mut head = ex.response_head(status);
    head.fields
        .append_known(Known::ContentType, file.content_type.as_bytes());
    if let Some(encoding) = encoding {
        head.fields
            .append_known(Known::ContentEncoding, encoding.token());
    }
    head.vary_accept_encoding = vary;
    Ok(local(head, body(content, 0..content.len)))
}

/// The file for a request path: the path itself, or a directory's first index file. A path
/// naming one of this server's own sidecars is missing.
fn find(
    options: &Options<'_>,
    root: &[u8],
    path: &[u8],
    catalog: &mut Catalog,
) -> Result<Rc<FileEntry>, Status> {
    let sidecar_exts = options
        .precompressed
        .iter()
        .map(|e| e.sidecar())
        .chain(options.etag_sidecar);
    for ext in sidecar_exts {
        if let Some(base) = path.strip_suffix(ext)
            && !base.ends_with(b"/")
            && catalog.probe(root, base)
        {
            return Err(Status::NOT_FOUND);
        }
    }
    let want = Want::new(options.precompressed, options.etag_sidecar);
    match catalog.lookup(root, &[path], &want) {
        Node::File(file) => Ok(file),
        Node::Missing => Err(Status::NOT_FOUND),
        Node::Dir => options
            .index
            .iter()
            .find_map(|index| match catalog.lookup(root, &[path, index], &want) {
                Node::File(file) => Some(file),
                _ => None,
            })
            .ok_or(Status::NOT_FOUND),
    }
}

fn body(content: &Content, range: Range<u64>) -> Body {
    match &content.data {
        Data::Small(bytes) => Body::Bytes(bytes.slice(range.start as usize..range.end as usize)),
        Data::Open(file) => Body::File(FileBody {
            file: Rc::clone(file),
            range,
        }),
    }
}

fn local(head: crate::msg::ResponseHead, body: Body) -> Response {
    Response {
        head,
        body,
        upgrade: None,
        local: true,
    }
}

/// Formats into a stack buffer (header values built without allocating).
fn fmt<'b>(buf: &'b mut [u8], args: std::fmt::Arguments<'_>) -> &'b [u8] {
    let mut cursor = &mut buf[..];
    cursor
        .write_fmt(args)
        .expect("header value fits its buffer");
    let left = cursor.len();
    let written = buf.len() - left;
    &buf[..written]
}

/// Fuzz entry points; not part of the API.
#[cfg(feature = "internals")]
pub mod harness {
    use super::*;
    use crate::exchange::{ConnInfo, ErrorInfo, Proto, Scheme};
    use crate::msg::{RequestHead, Version};
    use crate::plan::{ListenerKey, ListenerKind};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::LazyLock;

    /// A served tree and its neighbours: `<base>/site` is the root, `<base>/secret` and
    /// `<base>/site-evil/x` lie outside it. Every file has a length of its own, so a body
    /// says which file it came from.
    struct Tree {
        root: Vec<u8>,
        /// By length: the bytes of each file under the root, sidecars included.
        inside: HashMap<u64, Vec<u8>>,
    }

    static TREE: LazyLock<Tree> = LazyLock::new(|| {
        let base =
            std::env::temp_dir().join(format!("upstreamer-fuzz-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut inside = HashMap::new();
        let mut write = |rel: &str, len: usize, within: bool| {
            let path: PathBuf = base.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut bytes = format!("{rel}:").into_bytes();
            bytes.extend(
                (0..)
                    .map(|i: u32| b'a' + (i % 26) as u8)
                    .take(len - bytes.len()),
            );
            std::fs::write(&path, &bytes).unwrap();
            if within {
                assert!(
                    inside.insert(len as u64, bytes).is_none(),
                    "{rel}: lengths repeat"
                );
            }
        };
        write("secret", 4000, false);
        write("site-evil/x", 4001, false);
        write("site/../secret.copy", 4002, false);
        for (i, rel) in [
            "site/index.html",
            "site/a.txt",
            "site/a.txt.gz",
            "site/dir/index.html",
            "site/dir/b.css",
            "site/dir/sub/c.js",
            "site/%2e%2e",
            "site/..a",
            "site/\u{fc}.txt",
            "site/with space",
            "site/q?x",
        ]
        .into_iter()
        .enumerate()
        {
            write(rel, 100 + 37 * i, true);
        }
        // Larger than a file kept in memory: answered from its descriptor.
        write("site/big.bin", SMALL + 5, true);
        std::fs::write(base.join("site/a.txt.etag"), "\"tag-a\"").unwrap();
        Tree {
            root: base.join("site").into_os_string().into_encoded_bytes(),
            inside,
        }
    });

    const SMALL: usize = catalog::SMALL_FILE as usize;
    static INDEX: LazyLock<Vec<Box<[u8]>>> = LazyLock::new(|| vec![Box::from(&b"index.html"[..])]);

    thread_local! {
        static CATALOG: std::cell::RefCell<Catalog> = std::cell::RefCell::default();
    }

    /// A clean path: starts with `/`, no empty, `.` or `..` segment but a trailing `/`.
    pub(crate) fn assert_clean(path: &[u8]) {
        assert_eq!(path.first(), Some(&b'/'), "{path:?}");
        let segments: Vec<&[u8]> = path[1..].split(|&b| b == b'/').collect();
        for (i, segment) in segments.iter().enumerate() {
            let last = i + 1 == segments.len();
            assert!(!segment.is_empty() || last, "an empty segment in {path:?}");
            assert!(
                *segment != b"." && *segment != b"..",
                "a dot segment in {path:?}"
            );
        }
    }

    /// A request for the file server, with header fields a client controls. The first byte
    /// picks the method (low two bits), an error route (bit 2) and a `stripPrefix /dir`
    /// before serving (bit 3); then the request-target, then `name: value` lines.
    ///
    /// The path the target cleans to is clean, cleans again to itself, and once joined to
    /// the root names nothing outside it. A stripped prefix leaves a target whose bytes clean
    /// to the path the routes saw. A response's body is bytes of a file under the root,
    /// ranges and validators included, and a range lies within its file.
    pub fn input(data: &[u8]) {
        let Some((&options, rest)) = data.split_first() else {
            return;
        };
        let mut lines = rest.split(|&b| b == b'\n');
        let target = lines.next().unwrap_or_default();
        let method: &[u8] = [&b"GET"[..], b"HEAD", b"POST", b"GET"][usize::from(options & 3)];
        let conn = ConnInfo {
            remote: "192.0.2.1:1000".parse().unwrap(),
            local_port: 443,
            scheme: Scheme::Https,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:443".parse().unwrap(),
                kind: ListenerKind::Https,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        if ex.req.set_line(method, target, Version::Http11).is_err() {
            return;
        }
        for line in lines {
            if let Some(at) = line.iter().position(|&b| b == b':')
                && line[..at].iter().all(|&b| crate::msg::is_tchar(b))
                && line[at + 1..]
                    .iter()
                    .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
            {
                ex.req.push_field(&line[..at], &line[at + 1..]);
            }
        }
        check_path(&ex.req);
        if options & 8 != 0 && ex.req.strip_prefix(b"/dir") {
            check_path(&ex.req);
            if ex.req.target() == crate::msg::Target::Original {
                let raw = ex.req.raw_target();
                let raw = raw.split(|&b| b == b'?').next().unwrap_or_default();
                let mut again = Vec::new();
                let span = crate::msg::clean_path(raw, &mut again);
                assert_eq!(
                    span.map(|s| s.get(&again)),
                    Some(ex.req.path().as_bytes()),
                    "the target sent upstream names another path than the routes saw"
                );
            }
        }
        if options & 4 != 0 {
            ex.error = Some(ErrorInfo {
                status: Status::NOT_FOUND,
            });
        }

        let tree = &*TREE;
        let root = ex.arena.push(&tree.root);
        let options = Options {
            precompressed: &[Encoding::Gzip],
            etag_sidecar: Some(b".etag"),
            index: &INDEX,
        };
        let served =
            CATALOG.with_borrow_mut(|catalog| serve_with(&options, root, &mut ex, catalog));
        let Ok(response) = served else {
            return;
        };
        let head = &response.head;
        let field = |name: &[u8]| {
            head.fields
                .live()
                .find(|(n, _, _)| *n == name)
                .map(|(_, v, _)| v.to_vec())
        };
        let body = match response.body {
            Body::Empty => Vec::new(),
            Body::Bytes(bytes) => bytes.to_vec(),
            Body::File(file) => {
                use std::os::unix::fs::FileExt;
                let mut bytes = vec![0; (file.range.end - file.range.start) as usize];
                file.file
                    .read_exact_at(&mut bytes, file.range.start)
                    .unwrap();
                bytes
            }
            _ => unreachable!("the file server answers from files"),
        };
        match head.status.code() {
            206 => {
                let range = field(b"content-range").expect("a 206 has a Content-Range");
                let range = std::str::from_utf8(&range).unwrap();
                let (span, len) = range
                    .strip_prefix("bytes ")
                    .unwrap()
                    .split_once('/')
                    .unwrap();
                let (first, last) = span.split_once('-').unwrap();
                let (first, last, len): (u64, u64, u64) = (
                    first.parse().unwrap(),
                    last.parse().unwrap(),
                    len.parse().unwrap(),
                );
                assert!(first <= last && last < len, "{range}");
                let file = tree
                    .inside
                    .get(&len)
                    .expect("a range of a file under the root");
                assert_eq!(body, file[first as usize..=last as usize]);
            }
            304 => assert!(body.is_empty()),
            416 => assert!(body.is_empty()),
            _ => {
                let file = tree.inside.get(&(body.len() as u64));
                assert_eq!(Some(&body), file, "a body that is no file under the root");
            }
        }
    }

    fn check_path(req: &RequestHead) {
        let path = req.path().as_bytes();
        assert_clean(path);
        // Cleaning is idempotent, from the wire (encoded) and from a rewrite (decoded).
        let mut encoded = Vec::new();
        for &b in path {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                encoded.push(b);
            } else {
                encoded.extend_from_slice(format!("%{b:02X}").as_bytes());
            }
        }
        let mut again = RequestHead::new();
        again
            .set_line(b"GET", &encoded, Version::Http11)
            .expect("a clean path parses");
        assert_eq!(again.path().as_bytes(), path);
        again
            .rewrite_parts(path, None)
            .expect("a clean path is a rewrite");
        assert_eq!(again.path().as_bytes(), path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ConnInfo, ErrorInfo, Proto, Scheme};
    use crate::msg::Version;
    use crate::plan::{ListenerKey, ListenerKind};
    use Encoding::{Br, Gzip, Zstd};
    use catalog::Limits;
    use std::os::unix::fs::FileExt;
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;
    use std::time::{Duration, SystemTime};

    static INDEX: LazyLock<Vec<Box<[u8]>>> = LazyLock::new(|| vec![Box::from(&b"index.html"[..])]);

    fn options<'a>(precompressed: &'a [Encoding], etag_sidecar: Option<&'a str>) -> Options<'a> {
        Options {
            precompressed,
            etag_sidecar: etag_sidecar.map(str::as_bytes),
            index: &INDEX,
        }
    }

    /// A copy of a fixture tree whose files all have mtime 1, laid out like a store path:
    /// the tree is `<prefix>/site`, and a store catalog treats `<prefix>/` as the store.
    struct Tree {
        dir: tempfile::TempDir,
    }

    impl Tree {
        fn fixture(name: &str) -> Tree {
            let tree = Tree::empty();
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/files")
                .join(name);
            copy_tree(&source, &tree.path(""));
            tree
        }
        fn empty() -> Tree {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("site")).unwrap();
            Tree { dir }
        }
        fn path(&self, rel: &str) -> PathBuf {
            let site = self.dir.path().join("site");
            if rel.is_empty() { site } else { site.join(rel) }
        }
        fn root(&self, rel: &str) -> Vec<u8> {
            self.path(rel).into_os_string().into_encoded_bytes()
        }
        fn read(&self, rel: &str) -> Vec<u8> {
            std::fs::read(self.path(rel)).unwrap()
        }
        /// A catalog that treats this tree as a store path.
        fn store_catalog(&self) -> Catalog {
            Catalog::with_limits(Limits {
                store: self.store_prefix(),
                ..Limits::default()
            })
        }
        fn store_prefix(&self) -> Box<[u8]> {
            let mut store = self.dir.path().as_os_str().as_encoded_bytes().to_vec();
            store.push(b'/');
            store.into()
        }
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
                set_mtime(&target, 1);
            }
        }
    }

    fn set_mtime(path: &Path, unix: u64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(unix);
        file.set_times(std::fs::FileTimes::new().set_modified(at).set_accessed(at))
            .unwrap();
    }

    fn request(method: &str, target: &str, headers: &[(&str, &str)]) -> Exchange {
        let conn = ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: 443,
            scheme: Scheme::Https,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:443".parse().unwrap(),
                kind: ListenerKind::Http,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.req
            .set_line(method.as_bytes(), target.as_bytes(), Version::Http11)
            .unwrap();
        for (name, value) in headers {
            ex.req.push_field(name.as_bytes(), value.as_bytes());
        }
        ex
    }

    #[derive(Debug)]
    struct Served {
        status: u16,
        headers: Vec<(String, String)>,
        vary_accept_encoding: bool,
        body: Vec<u8>,
        /// Whether the body is sent from an open descriptor rather than memory.
        from_fd: bool,
    }

    impl Served {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }
    }

    fn serve_in(
        options: &Options<'_>,
        root: &[u8],
        ex: &mut Exchange,
        catalog: &mut Catalog,
    ) -> Result<Served, u16> {
        let root = ex.arena.push(root);
        let resp = serve_with(options, root, ex, catalog).map_err(Status::code)?;
        let (body, from_fd) = match resp.body {
            Body::Empty => (Vec::new(), false),
            Body::Bytes(bytes) => (bytes.to_vec(), false),
            Body::File(file) => {
                let mut buf = vec![0; (file.range.end - file.range.start) as usize];
                file.file.read_exact_at(&mut buf, file.range.start).unwrap();
                (buf, true)
            }
            _ => panic!("a file response has a file body"),
        };
        Ok(Served {
            status: resp.head.status.code(),
            headers: resp
                .head
                .fields
                .live()
                .map(|(n, v, _)| {
                    (
                        String::from_utf8(n.to_vec()).unwrap(),
                        String::from_utf8(v.to_vec()).unwrap(),
                    )
                })
                .collect(),
            vary_accept_encoding: resp.head.vary_accept_encoding,
            body,
            from_fd,
        })
    }

    fn get(
        options: &Options<'_>,
        root: &[u8],
        catalog: &mut Catalog,
        target: &str,
        headers: &[(&str, &str)],
    ) -> Result<Served, u16> {
        serve_in(options, root, &mut request("GET", target, headers), catalog)
    }

    #[test]
    fn heimdall_index_in_brotli_with_the_brotli_files_etag() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        let resp = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("accept-encoding", "br")],
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("content-encoding"), Some("br"));
        assert_eq!(resp.body, tree.read("index.html.br"));
        assert_eq!(
            resp.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        let etag = resp.header("etag").unwrap();
        assert_eq!(
            etag,
            String::from_utf8(tree.read("index.html.br.etag")).unwrap(),
            "the content of the brotli file's own ETag sidecar"
        );
        assert_eq!(etag.len(), 26, "heimdall's content-hash tags are 26 bytes");
        assert_eq!(resp.header("accept-ranges"), Some("bytes"));
        assert_eq!(resp.header("last-modified"), None, "store mtimes are 1");
        assert!(resp.vary_accept_encoding);

        let gzip = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("accept-encoding", "gzip, deflate")],
        )
        .unwrap();
        assert_eq!(gzip.header("content-encoding"), Some("gzip"));
        assert_eq!(gzip.body, tree.read("index.html.gz"));
        assert_eq!(
            gzip.header("etag"),
            Some(r#""Gz8hR3nYw5KqD2fM7tV0xA9b""#),
            "each encoding has its own ETag"
        );

        let plain = get(&site, &tree.root(""), &mut catalog, "/index.html", &[]).unwrap();
        assert_eq!(plain.header("content-encoding"), None);
        assert_eq!(plain.body, tree.read("index.html"));
        assert_eq!(plain.header("etag"), Some(r#""Vh2c1Qx0aZ3kLm9PqR7sT4uW""#));
        assert!(
            plain.vary_accept_encoding,
            "the answer depends on Accept-Encoding"
        );
    }

    #[test]
    fn heimdall_root_revalidates_to_304_by_the_sidecar_etag() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        let br = r#""Br4kQ9mXv2LpT7cN1sW6yZ0e""#;
        let identity = r#""Vh2c1Qx0aZ3kLm9PqR7sT4uW""#;
        let resp = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/",
            &[("accept-encoding", "br"), ("if-none-match", br)],
        )
        .unwrap();
        assert_eq!(resp.status, 304);
        assert_eq!(resp.header("etag"), Some(br));
        assert!(resp.body.is_empty());
        assert!(resp.vary_accept_encoding);

        let plain = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/",
            &[("if-none-match", identity)],
        )
        .unwrap();
        assert_eq!((plain.status, plain.header("etag")), (304, Some(identity)));

        let switched = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/",
            &[("accept-encoding", "br"), ("if-none-match", identity)],
        )
        .unwrap();
        assert_eq!(
            (switched.status, switched.header("etag")),
            (200, Some(br)),
            "the identity tag does not validate the brotli representation"
        );

        let changed = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/",
            &[("if-none-match", r#""other""#)],
        )
        .unwrap();
        assert_eq!(changed.status, 200);
        assert_eq!(changed.body, tree.read("index.html"));
    }

    #[test]
    fn heimdall_immutable_assets_and_missing_ones() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let immutable = options(&[Br, Gzip], None);
        let asset = "/_app/immutable/entry/app.Bk3d9f.js";
        let resp = get(
            &immutable,
            &tree.root(""),
            &mut catalog,
            asset,
            &[("accept-encoding", "gzip, br")],
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("content-encoding"), Some("br"));
        assert_eq!(
            resp.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(
            resp.header("cache-control"),
            None,
            "caching is the config's header"
        );
        let etag = resp.header("etag").unwrap();
        assert!(
            negotiate::entity_tag(etag.as_bytes()).is_some_and(|(weak, _)| !weak),
            "{etag}"
        );

        assert_eq!(
            get(
                &immutable,
                &tree.root(""),
                &mut catalog,
                "/_app/immutable/missing.js",
                &[]
            )
            .unwrap_err(),
            404
        );
    }

    #[test]
    fn sidecars_are_never_served() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        for path in [
            "/index.html.etag",
            "/index.html.br",
            "/index.html.gz",
            "/index.html.br.etag",
            "/index.html.gz.etag",
            "/sw.js.etag",
            "/_app/immutable/entry/app.Bk3d9f.js.gz",
        ] {
            assert_eq!(
                get(&site, &tree.root(""), &mut catalog, path, &[]).unwrap_err(),
                404,
                "{path}"
            );
        }
    }

    #[test]
    fn a_compressed_file_without_a_base_is_an_ordinary_file() {
        let tree = Tree::empty();
        std::fs::write(tree.path("notes.tar.gz"), b"\x1f\x8b archive").unwrap();
        let mut catalog = tree.store_catalog();
        let resp = get(
            &options(&[Gzip], None),
            &tree.root(""),
            &mut catalog,
            "/notes.tar.gz",
            &[("accept-encoding", "gzip")],
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("content-type"), Some("application/gzip"));
        assert_eq!(resp.header("content-encoding"), None);
        assert_eq!(resp.body, b"\x1f\x8b archive");
    }

    #[test]
    fn portfolio_assets_follow_q_values_then_config_order() {
        let tree = Tree::fixture("portfolio");
        let mut catalog = tree.store_catalog();
        let assets = options(&[Br, Zstd, Gzip], None);
        let css = "/_astro/index.Bx1c2d.css";
        let encoded = |catalog: &mut Catalog, accept: &str| {
            let resp = get(
                &assets,
                &tree.root(""),
                catalog,
                css,
                &[("accept-encoding", accept)],
            )
            .unwrap();
            (
                resp.header("content-encoding").map(str::to_owned),
                resp.body,
            )
        };
        assert_eq!(
            encoded(&mut catalog, "gzip, deflate, br, zstd"),
            (Some("br".into()), tree.read("_astro/index.Bx1c2d.css.br"))
        );
        assert_eq!(
            encoded(&mut catalog, "gzip, zstd"),
            (
                Some("zstd".into()),
                tree.read("_astro/index.Bx1c2d.css.zst")
            )
        );
        assert_eq!(
            encoded(&mut catalog, "zstd;q=0.5, gzip"),
            (Some("gzip".into()), tree.read("_astro/index.Bx1c2d.css.gz"))
        );
        assert_eq!(
            encoded(&mut catalog, "deflate"),
            (None, tree.read("_astro/index.Bx1c2d.css"))
        );
        let plain = get(&assets, &tree.root(""), &mut catalog, css, &[]).unwrap();
        assert_eq!(
            plain.header("content-type"),
            Some("text/css; charset=utf-8")
        );
        assert_eq!(plain.header("accept-ranges"), Some("bytes"));
        assert_eq!(
            get(
                &assets,
                &tree.root(""),
                &mut catalog,
                "/_astro/index.Bx1c2d.css.zst",
                &[]
            )
            .unwrap_err(),
            404
        );
    }

    #[test]
    fn portfolio_pages_from_the_selected_tree() {
        let tree = Tree::fixture("portfolio");
        let mut catalog = tree.store_catalog();
        let pages = options(&[Br, Zstd, Gzip], Some(".etag"));
        let root = tree.root("site/e0/main/en");

        let home = get(
            &pages,
            &root,
            &mut catalog,
            "/",
            &[("accept-encoding", "zstd, gzip")],
        )
        .unwrap();
        assert_eq!(home.header("content-encoding"), Some("zstd"));
        assert_eq!(home.body, tree.read("site/e0/main/en/index.html.zst"));
        let zstd_tag = home.header("etag").unwrap();
        assert_ne!(
            zstd_tag, r#""e0-main-en-index""#,
            "without `index.html.zst.etag` the zstd file's tag is derived from it"
        );
        let plain = get(&pages, &root, &mut catalog, "/", &[]).unwrap();
        assert_eq!(plain.header("etag"), Some(r#""e0-main-en-index""#));

        let post = get(
            &pages,
            &root,
            &mut catalog,
            "/blog/hello",
            &[("accept-encoding", "br")],
        )
        .unwrap();
        assert_eq!(post.status, 200);
        assert_eq!(
            post.header("content-encoding"),
            None,
            "the post has no sidecars"
        );
        assert!(!post.vary_accept_encoding);
        assert_eq!(
            post.body,
            tree.read("site/e0/main/en/blog/hello/index.html")
        );
        assert_eq!(post.header("etag"), Some(r#""e0-main-en-blog-hello""#));

        let markdown = get(&pages, &root, &mut catalog, "/_md/blog.md", &[]).unwrap();
        assert_eq!(
            markdown.header("content-type"),
            Some("text/markdown; charset=utf-8")
        );
        assert_eq!(markdown.header("etag"), Some(r#""e0-main-en-md-blog""#));

        assert_eq!(
            get(&pages, &root, &mut catalog, "/blog/missing", &[]).unwrap_err(),
            404
        );
        assert_eq!(
            get(&pages, &root, &mut catalog, "/blog", &[]).unwrap_err(),
            404,
            "a directory without an index"
        );

        let statics = tree.root("static");
        let robots = get(&pages, &statics, &mut catalog, "/robots.txt", &[]).unwrap();
        assert_eq!(
            robots.header("content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(robots.header("etag"), Some(r#""r0b0tsTxtEtag01""#));
        assert_eq!(
            get(&pages, &statics, &mut catalog, "/robots.txt.etag", &[]).unwrap_err(),
            404
        );
    }

    #[test]
    fn every_core_derives_the_same_etag() {
        let tree = Tree::fixture("portfolio");
        let assets = options(&[Br, Zstd, Gzip], Some(".etag"));
        let etag = |catalog: &mut Catalog| {
            get(&assets, &tree.root("static"), catalog, "/favicon.ico", &[])
                .unwrap()
                .header("etag")
                .map(str::to_owned)
        };
        let (mut core0, mut core1) = (tree.store_catalog(), tree.store_catalog());
        let first = etag(&mut core0).unwrap();
        assert_eq!(etag(&mut core1).unwrap(), first);
        let revalidated = get(
            &assets,
            &tree.root("static"),
            &mut core1,
            "/favicon.ico",
            &[("if-none-match", &first)],
        )
        .unwrap();
        assert_eq!(revalidated.status, 304);
    }

    #[test]
    fn error_pages_keep_the_error_status_and_skip_conditionals() {
        let tree = Tree::fixture("portfolio");
        let mut catalog = tree.store_catalog();
        let errors = options(&[Br, Zstd, Gzip], None);
        let root = tree.root("site/e0/main/en");
        let first = get(&errors, &root, &mut catalog, "/404.html", &[]).unwrap();
        let etag = first.header("etag").unwrap().to_owned();
        let mut ex = request(
            "POST",
            "/404.html",
            &[
                ("accept-encoding", "br"),
                ("if-none-match", &etag),
                ("range", "bytes=0-9"),
            ],
        );
        ex.error = Some(ErrorInfo {
            status: Status::NOT_FOUND,
        });
        let resp = serve_in(&errors, &root, &mut ex, &mut catalog).unwrap();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.header("content-encoding"), Some("br"));
        assert_eq!(resp.body, tree.read("site/e0/main/en/404.html.br"));
        assert_eq!(
            resp.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(resp.header("etag"), None);
        assert_eq!(resp.header("content-range"), None);

        let mut missing = request("GET", "/nope.html", &[]);
        missing.error = Some(ErrorInfo {
            status: Status::NOT_FOUND,
        });
        assert_eq!(
            serve_in(&errors, &root, &mut missing, &mut catalog).unwrap_err(),
            404
        );
    }

    #[test]
    fn single_ranges_on_the_identity_representation() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        let index = tree.read("index.html");
        let len = index.len();

        let part = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("accept-encoding", "br"), ("range", "bytes=0-9")],
        )
        .unwrap();
        assert_eq!(part.status, 206);
        assert_eq!(part.header("content-encoding"), None);
        assert_eq!(
            part.header("content-range").unwrap(),
            format!("bytes 0-9/{len}")
        );
        assert_eq!(part.body, &index[..10]);

        let tail = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("range", "bytes=-5")],
        )
        .unwrap();
        assert_eq!(
            tail.header("content-range").unwrap(),
            format!("bytes {}-{}/{len}", len - 5, len - 1)
        );
        assert_eq!(tail.body, &index[len - 5..]);

        let past = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("range", &format!("bytes={len}-"))],
        )
        .unwrap();
        assert_eq!(past.status, 416);
        assert_eq!(
            past.header("content-range").unwrap(),
            format!("bytes */{len}")
        );
        assert!(past.body.is_empty());

        let multi = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("accept-encoding", "br"), ("range", "bytes=0-1,5-6")],
        )
        .unwrap();
        assert_eq!(
            (multi.status, multi.header("content-encoding")),
            (200, Some("br"))
        );

        let stale = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[("range", "bytes=0-9"), ("if-range", r#""old""#)],
        )
        .unwrap();
        assert_eq!((stale.status, stale.body.len()), (200, len));
        let current = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/index.html",
            &[
                ("range", "bytes=0-9"),
                ("if-range", r#""Vh2c1Qx0aZ3kLm9PqR7sT4uW""#),
            ],
        )
        .unwrap();
        assert_eq!(current.status, 206);

        let head = serve_in(
            &site,
            &tree.root(""),
            &mut request("HEAD", "/index.html", &[("range", "bytes=0-9")]),
            &mut catalog,
        )
        .unwrap();
        assert_eq!(
            (head.status, head.body.len()),
            (200, len),
            "HEAD ignores Range and carries the length"
        );
    }

    #[test]
    fn only_get_and_head() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
            let err = serve_in(
                &site,
                &tree.root(""),
                &mut request(method, "/index.html", &[]),
                &mut catalog,
            )
            .unwrap_err();
            assert_eq!(err, 405, "{method}");
        }
    }

    #[test]
    fn large_files_are_sent_from_their_descriptor() {
        let tree = Tree::empty();
        let data: Vec<u8> = (0..200 * 1024u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(tree.path("disk.img"), &data).unwrap();
        let mut catalog = tree.store_catalog();
        let site = options(&[], None);
        let whole = get(&site, &tree.root(""), &mut catalog, "/disk.img", &[]).unwrap();
        assert!(whole.from_fd);
        assert_eq!(whole.body, data);
        let part = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/disk.img",
            &[("range", "bytes=150000-150009")],
        )
        .unwrap();
        assert_eq!(part.status, 206);
        assert_eq!(
            part.header("content-range"),
            Some("bytes 150000-150009/204800")
        );
        assert_eq!(part.body, &data[150000..150010]);
    }

    #[test]
    fn mutable_files_carry_last_modified_and_answer_if_modified_since() {
        let tree = Tree::empty();
        std::fs::write(tree.path("page.html"), b"<p>hi</p>").unwrap();
        set_mtime(&tree.path("page.html"), 784111777);
        let mut catalog = Catalog::default();
        let site = options(&[], None);
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let resp = get(&site, &tree.root(""), &mut catalog, "/page.html", &[]).unwrap();
        assert_eq!(resp.header("last-modified"), Some(date));
        let since = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/page.html",
            &[("if-modified-since", date)],
        )
        .unwrap();
        assert_eq!(since.status, 304);
        let earlier = get(
            &site,
            &tree.root(""),
            &mut catalog,
            "/page.html",
            &[("if-modified-since", "Sat, 05 Nov 1994 08:49:37 GMT")],
        )
        .unwrap();
        assert_eq!(earlier.status, 200);
    }

    #[test]
    fn an_invalid_etag_sidecar_is_ignored() {
        let tree = Tree::empty();
        std::fs::write(tree.path("a.txt"), b"a").unwrap();
        std::fs::write(tree.path("a.txt.etag"), b"not quoted\n").unwrap();
        std::fs::write(tree.path("b.txt"), b"b").unwrap();
        std::fs::write(tree.path("b.txt.etag"), b"\"b\"\r\nSet-Cookie: x=1").unwrap();
        let mut catalog = tree.store_catalog();
        let site = options(&[], Some(".etag"));
        for file in ["/a.txt", "/b.txt"] {
            let etag = get(&site, &tree.root(""), &mut catalog, file, &[])
                .unwrap()
                .header("etag")
                .unwrap()
                .to_owned();
            assert!(negotiate::entity_tag(etag.as_bytes()).is_some(), "{etag}");
            assert!(
                !etag.contains("quoted") && !etag.contains("Set-Cookie"),
                "{etag}"
            );
        }
    }

    #[test]
    fn warm_store_requests_need_no_file_system() {
        let tree = Tree::fixture("heimdall");
        let mut catalog = Catalog::with_limits(Limits {
            store: tree.store_prefix(),
            revalidate: Duration::ZERO,
            ..Limits::default()
        });
        let site = options(&[Br, Gzip], Some(".etag"));
        let root = tree.root("");
        let index = tree.read("index.html.br");
        let warm = |catalog: &mut Catalog| {
            (
                get(&site, &root, catalog, "/", &[("accept-encoding", "br")]).unwrap(),
                get(&site, &root, catalog, "/_app/immutable/missing.js", &[]).unwrap_err(),
                get(&site, &root, catalog, "/index.html.etag", &[]).unwrap_err(),
            )
        };
        warm(&mut catalog);
        std::fs::remove_dir_all(tree.path("")).unwrap();
        let (resp, missing, sidecar) = warm(&mut catalog);
        assert_eq!(resp.body, index, "served from the catalog");
        assert_eq!(resp.header("etag"), Some(r#""Br4kQ9mXv2LpT7cN1sW6yZ0e""#));
        assert_eq!((missing, sidecar), (404, 404));
        catalog.retain_immutable();
        assert_eq!(
            warm(&mut catalog).0.body,
            index,
            "a new plan keeps store entries"
        );
    }

    #[test]
    fn mutable_entries_are_revalidated() {
        let tree = Tree::empty();
        std::fs::write(tree.path("a.txt"), b"one").unwrap();
        let site = options(&[], None);
        let root = tree.root("");

        let mut cached = Catalog::default();
        let mut expired = Catalog::with_limits(Limits {
            revalidate: Duration::ZERO,
            ..Limits::default()
        });
        for catalog in [&mut cached, &mut expired] {
            assert_eq!(
                get(&site, &root, catalog, "/a.txt", &[]).unwrap().body,
                b"one"
            );
        }
        std::fs::remove_file(tree.path("a.txt")).unwrap();
        assert_eq!(
            get(&site, &root, &mut cached, "/a.txt", &[]).unwrap().body,
            b"one",
            "within a second"
        );
        assert_eq!(
            get(&site, &root, &mut expired, "/a.txt", &[]).unwrap_err(),
            404
        );
        cached.retain_immutable();
        assert_eq!(
            get(&site, &root, &mut cached, "/a.txt", &[]).unwrap_err(),
            404,
            "a new plan drops it"
        );

        std::fs::write(tree.path("a.txt"), b"two").unwrap();
        assert_eq!(
            get(&site, &root, &mut expired, "/a.txt", &[]).unwrap().body,
            b"two"
        );
    }

    #[test]
    fn eviction_keeps_answers_right() {
        let tree = Tree::fixture("portfolio");
        let mut catalog = Catalog::with_limits(Limits {
            entries: 3,
            small_bytes: 300,
            store: tree.store_prefix(),
            ..Limits::default()
        });
        let pages = options(&[Br, Zstd, Gzip], Some(".etag"));
        let root = tree.root("site/e0/main/en");
        for _ in 0..3 {
            for (path, file) in [
                ("/", "index.html"),
                ("/blog/hello", "blog/hello/index.html"),
                ("/_md/blog.md", "_md/blog.md"),
                ("/404.html", "404.html"),
            ] {
                let resp = get(&pages, &root, &mut catalog, path, &[]).unwrap();
                assert_eq!(
                    resp.body,
                    tree.read(&format!("site/e0/main/en/{file}")),
                    "{path}"
                );
            }
        }
    }

    #[test]
    fn probes_see_files_and_directories() {
        let tree = Tree::fixture("portfolio");
        let mut catalog = tree.store_catalog();
        let root = tree.root("site/e0/main/en");
        assert!(catalog.probe(&root, b"/blog/hello/index.html"));
        assert!(catalog.probe(&root, b"//blog/hello//index.html"));
        assert!(catalog.probe(&root, b"/blog/hello/"));
        assert!(!catalog.probe(&root, b"/blog/hello"));
        assert!(!catalog.probe(&root, b"/index.html/"));
        assert!(!catalog.probe(&root, b"/blog/../index.html"));
    }

    /// Run the test binary under `strace -f -e trace=%file,%desc` with `--ignored --exact` and
    /// `--nocapture`: no file syscall may appear between the two marker writes.
    #[test]
    #[ignore = "a probe for strace"]
    fn strace_warm_store_requests() {
        use std::io::Write as _;
        let tree = Tree::fixture("heimdall");
        let mut catalog = tree.store_catalog();
        let site = options(&[Br, Gzip], Some(".etag"));
        let root = tree.root("");
        let mut requests = |n| {
            for _ in 0..n {
                get(
                    &site,
                    &root,
                    &mut catalog,
                    "/",
                    &[("accept-encoding", "br")],
                )
                .unwrap();
                get(
                    &site,
                    &root,
                    &mut catalog,
                    "/_app/immutable/entry/app.Bk3d9f.js",
                    &[],
                )
                .unwrap();
                get(
                    &site,
                    &root,
                    &mut catalog,
                    "/_app/immutable/missing.js",
                    &[],
                )
                .unwrap_err();
            }
        };
        requests(1);
        std::io::stderr().write_all(b"warm-begin\n").unwrap();
        requests(1000);
        std::io::stderr().write_all(b"warm-end\n").unwrap();
    }
}
