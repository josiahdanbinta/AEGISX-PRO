#!/bin/sh
# AEGISX mTLS Certificate Generator
# Generates CA, server, and client certificates for TLS 1.3 + mTLS

set -e

CERT_DIR="${1:-./certs}"
mkdir -p "$CERT_DIR"

echo "Generating CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$CERT_DIR/ca.key"
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/O=AEGISX/CN=AEGISX Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "Generating server certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$CERT_DIR/server.key"
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/O=AEGISX/CN=aegisx.local"

cat > "$CERT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:aegisx.local,DNS:*.aegisx.local,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -days 365 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -extfile "$CERT_DIR/server.ext"

echo "Generating client certificate for service-to-service mTLS..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$CERT_DIR/client.key"
openssl req -new -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/O=AEGISX/CN=backend-client"

cat > "$CERT_DIR/client.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -days 365 \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -extfile "$CERT_DIR/client.ext"

chmod 600 "$CERT_DIR"/*.key
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.ext

echo ""
echo "Certificates generated in $CERT_DIR/:"
ls -la "$CERT_DIR/"
echo ""
echo "Usage:"
echo "  CA:          $CERT_DIR/ca.crt"
echo "  Server cert: $CERT_DIR/server.crt, server.key"
echo "  Client cert: $CERT_DIR/client.crt, client.key"
echo ""
echo "To enable mTLS in nginx.conf, uncomment the SSL/mTLS section."
echo "To test mTLS: curl --cacert $CERT_DIR/ca.crt --cert $CERT_DIR/client.crt --key $CERT_DIR/client.key https://localhost:443/api/health"
