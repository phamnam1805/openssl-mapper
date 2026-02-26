#!/usr/bin/env bash
# immediately bail if any command fails
set -e

OUTPUT_DIR="./self-signed-certs"

mkdir -p "$OUTPUT_DIR"

echo "generating self-signed server private key and certificate"
openssl req \
    -new \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -keyout "$OUTPUT_DIR/server-key.pem" \
    -out    "$OUTPUT_DIR/server-cert.pem" \
    -days   65536 \
    -config config/self-signed-server.cnf \
    -extensions self_signed_cert

echo "exporting server private key to DER format"
openssl pkcs8 \
    -topk8 \
    -inform  PEM \
    -outform DER \
    -nocrypt \
    -in  "$OUTPUT_DIR/server-key.pem" \
    -out "$OUTPUT_DIR/server-key.der"

echo "verifying generated certificate"
openssl x509 -in "$OUTPUT_DIR/server-cert.pem" -text -noout | grep -E "Issuer|Subject|Not (Before|After)|DNS:|IP:"

echo "done — files written to $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"
