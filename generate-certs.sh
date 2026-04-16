# immediately bail if any command fails
set -e

# Set output directory
OUTPUT_DIR="./certs"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "generating CA private key and certificate"
openssl req -nodes -new -x509 -keyout "$OUTPUT_DIR/ca-key.pem" -out "$OUTPUT_DIR/ca-cert.pem" -days 65536 -config config/ca.cnf

# secp384r1 is an arbitrarily chosen curve that is supported by the default
# security policy in s2n-tls.
# https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#chart-security-policy-version-to-supported-curvesgroups
echo "generating server private key and CSR"
openssl req -new -nodes -newkey rsa:2048 -keyout "$OUTPUT_DIR/server-key.pem" -out "$OUTPUT_DIR/server.csr" -config config/server.cnf

echo "generating client private key and CSR"
openssl req -new -nodes -newkey rsa:2048 -keyout "$OUTPUT_DIR/client-key.pem" -out "$OUTPUT_DIR/client.csr" -config config/client.cnf

echo "generating server certificate and signing it"
openssl x509 -days 65536 -req -in "$OUTPUT_DIR/server.csr" -CA "$OUTPUT_DIR/ca-cert.pem" -CAkey "$OUTPUT_DIR/ca-key.pem" -CAcreateserial -out "$OUTPUT_DIR/server-cert.pem" -extensions req_ext -extfile config/server.cnf

echo "generating client certificate and signing it"
openssl x509 -days 65536 -req -in "$OUTPUT_DIR/client.csr" -CA "$OUTPUT_DIR/ca-cert.pem" -CAkey "$OUTPUT_DIR/ca-key.pem" -CAcreateserial -out "$OUTPUT_DIR/client-cert.pem" -extensions req_ext -extfile config/client.cnf

echo "verifying generated certificates"
openssl verify -CAfile "$OUTPUT_DIR/ca-cert.pem" "$OUTPUT_DIR/server-cert.pem"
openssl verify -CAfile "$OUTPUT_DIR/ca-cert.pem" "$OUTPUT_DIR/client-cert.pem"

echo "exporting server private key to DER format"
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in "$OUTPUT_DIR/server-key.pem" -out "$OUTPUT_DIR/server-key.der"

echo "cleaning up temporary files"
rm "$OUTPUT_DIR/server.csr"
rm "$OUTPUT_DIR/client.csr"
# rm "$OUTPUT_DIR/ca-key.pem"