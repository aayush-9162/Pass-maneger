#!/usr/bin/env bash
#
# Generate a TLS certificate for a LAN deployment.
#
#   ./scripts/generate-lan-cert.sh 192.168.4.103
#
# On Windows, run this from Git Bash (it ships the openssl this script needs).
#
# Only needed for HTTPS - plain HTTP needs no certificate.
#
# The certificate covers the IP itself and its nip.io names -
# 192-168-4-103.nip.io and 192.168.4.103.nip.io - which public DNS resolves back
# to the IP. Google sign-in refuses a bare IP as an origin, so the console is
# reached by a nip.io name.
#
# The certificate authority is created once and reused on later runs, so a new
# IP only needs a new server certificate - client machines that already trust
# the CA keep trusting it. Delete ca.key and ca.crt to start over.
#
# ---------------------------------------------------------------------------
# Why a small CA and not just a self-signed certificate
# ---------------------------------------------------------------------------
# A bare self-signed leaf certificate cannot be made to work reliably in modern
# browsers: installing a leaf in the trust store leaves Chrome unable to build a
# chain, and it still reports ERR_CERT_AUTHORITY_INVALID.
#
# So this creates a two-level chain:
#
#   ca.crt      a tiny certificate authority - install this ONCE on each machine
#               that will use the console
#   server.crt  the server certificate, signed by that CA, carrying the LAN IP
#               in its subjectAltName
#
# Browsers require the address to appear in subjectAltName. A Common Name alone
# has not been accepted since Chrome 58, which is the single most common reason
# hand-rolled LAN certificates fail.
#
# Validity is 397 days: Apple and Chrome reject server certificates valid for
# more than 398 days, regardless of who issued them.
# ---------------------------------------------------------------------------

set -euo pipefail

# Git Bash / MSYS2 rewrites arguments that look like absolute POSIX paths, which
# turns OpenSSL's "/CN=..." subject into "C:/Program Files/Git/CN=...". Both
# variables are ignored on Linux and macOS.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

IP="${1:-}"
OUT_DIR="${2:-backend/certs}"

if [[ -z "$IP" ]]; then
  echo "Usage: $0 <lan-ip> [output-dir]" >&2
  echo "Example: $0 192.168.4.103" >&2
  exit 1
fi

if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "Error: '$IP' is not an IPv4 address." >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl not found. On Windows, run this from Git Bash." >&2
  exit 1
fi

# OpenSSL writes key-generation progress to stderr, which would bury a real
# error. Capture it and surface it only when the command actually fails.
run_openssl() {
  local description="$1"
  shift

  local log
  log="$(mktemp)"

  if ! openssl "$@" >"$log" 2>&1; then
    echo "Error: $description failed." >&2
    cat "$log" >&2
    rm -f "$log"
    exit 1
  fi

  rm -f "$log"
}

NIP_DASHED="${IP//./-}.nip.io"
NIP_DOTTED="$IP.nip.io"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if [[ -f ca.key && -f ca.crt ]]; then
  echo "==> Reusing the existing certificate authority (ca.crt)"
else
  echo "==> Generating a local certificate authority"
  run_openssl "certificate authority generation" \
    req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/CN=PassM Internal CA/O=PassM" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

echo "==> Generating the server key and signing request"
run_openssl "server key generation" \
  req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=$NIP_DASHED/O=PassM"

# The extensions that actually matter live here, not in the CSR: a CA is free to
# ignore anything a CSR requests, so they are supplied at signing time.
cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$NIP_DASHED,DNS:$NIP_DOTTED,IP:$IP,IP:127.0.0.1,DNS:localhost
EOF

echo "==> Signing the server certificate for $NIP_DASHED ($IP)"
run_openssl "certificate signing" \
  x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 397 -sha256 -extfile server.ext

# Private keys must not be world readable. (No effect on Windows/NTFS, where
# access is governed by ACLs - restrict the directory there instead.)
chmod 600 ca.key server.key 2>/dev/null || true
rm -f server.csr server.ext

echo
echo "Verifying the result:"
openssl x509 -in server.crt -noout -subject -dates \
  -ext subjectAltName | sed 's/^/  /'

echo
echo "Files written to $(pwd):"
echo "  ca.crt      install this on every client machine (see below)"
echo "  server.crt  server certificate"
echo "  server.key  server private key - never copy this off the server"
echo
echo "1. Point the API at the certificate (backend/.env):"
echo "     HTTPS_ENABLED=true"
echo "     TLS_CERT_PATH=certs/server.crt"
echo "     TLS_KEY_PATH=certs/server.key"
echo
echo "2. Trust the CA on each client machine:"
echo "     Windows  certutil -addstore -f ROOT ca.crt        (run as Administrator)"
echo "     macOS    sudo security add-trusted-cert -d -r trustRoot \\"
echo "                -k /Library/Keychains/System.keychain ca.crt"
echo "     Linux    sudo cp ca.crt /usr/local/share/ca-certificates/passm-ca.crt \\"
echo "                && sudo update-ca-certificates"
echo "     Firefox keeps its own store: Settings -> Privacy & Security ->"
echo "     Certificates -> View Certificates -> Authorities -> Import"
echo
echo "3. Browse to https://$NIP_DASHED:4000"
echo "   (add that origin to the Google OAuth client's Authorised JavaScript origins)"
echo
echo "Re-run this script before the certificate expires in 397 days."
