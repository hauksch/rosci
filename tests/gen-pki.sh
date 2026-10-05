#!/usr/bin/env bash
# Generates the throwaway test PKI for the e2e suite: five self-signed
# RSA-2048 identities and three PKCS#12 bundles. Everything lands in the
# directory given as $1, which lives in a tempdir and dies with the test.
# No real certificates were harmed — or used — in the making of this build.
set -euo pipefail
umask 077

OUT="${1:?usage: gen-pki.sh <output-dir>}"
PIN="${2:-testpin}"
mkdir -p "$OUT"
cd "$OUT"

gen() { # gen <name>
  openssl req -x509 -newkey rsa:2048 -keyout "$1.key" -out "$1.pem" \
    -days 2 -nodes -subj "/CN=$1/O=rosci-test/C=DE" \
    -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment" \
   
}

gen client-sign
gen client-cipher
gen recipient-cipher
gen intermed-sign
gen intermed-cipher

openssl pkcs12 -export -inkey client-sign.key -in client-sign.pem \
  -passout "pass:$PIN" -out client-sign.p12
openssl pkcs12 -export -inkey client-cipher.key -in client-cipher.pem \
  -passout "pass:$PIN" -out client-cipher.p12
openssl pkcs12 -export -inkey intermed-cipher.key -in intermed-cipher.pem \
  -passout "pass:$PIN" -out intermed-cipher.p12

echo "PKI ready in $OUT"
