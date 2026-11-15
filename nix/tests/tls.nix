# A test CA and a certificate for *.example.test signed by it, for the hosts that serve files
# outside ACME. Clients trust `ca.pem`.
{ pkgs }:
pkgs.runCommand "upstreamer-test-tls" { nativeBuildInputs = [ pkgs.openssl ]; } ''
  mkdir "$out"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj /CN=upstreamer-test-ca -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout ca.key -out "$out/ca.pem"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj /CN=example.test -keyout "$out/key.pem" -out leaf.csr
  printf '%s\n' 'subjectAltName=DNS:*.example.test' 'basicConstraints=CA:FALSE' \
    'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
    'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' > leaf.ext
  openssl x509 -req -in leaf.csr -CA "$out/ca.pem" -CAkey ca.key -CAcreateserial -days 3650 \
    -extfile leaf.ext -out "$out/cert.pem"
''
