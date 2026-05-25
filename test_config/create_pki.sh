#!/bin/sh

set -e
# Make a self-signed CA certificate.
openssl req -x509 -subj "/CN=Oxide VPN Test CA" -newkey ed25519 -keyout ca/ca.key -out ca/ca.crt -noenc -days 3650

# Make a server certificate.
openssl req -CA ca/ca.crt -CAkey ca/ca.key -subj "/CN=Oxide VPN Test Server" -newkey ed25519 \
            -keyout server/server.key -out server/server.crt -noenc -days 3650 -addext "keyUsage=digitalSignature" \
            -addext "extendedKeyUsage=serverAuth"

# Make a client certificate.
openssl req -CA ca/ca.crt -CAkey ca/ca.key -subj "/CN=Oxide VPN Test Client" -newkey ed25519 \
            -keyout client/client.key -out client/client.crt -noenc -days 3650 -addext "keyUsage=digitalSignature" \
            -addext "extendedKeyUsage=clientAuth"
