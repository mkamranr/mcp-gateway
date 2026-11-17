#!/bin/sh
# Throwaway PKI for the agent OAuth CI job: written to .github/oauth/pki/. Never use these outside CI.
set -eu
out="$(dirname "$0")/pki"
mkdir -p "$out"
cd "$out"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/O=MCP-Gateway CI/CN=IdP CA" -keyout idp-ca.key \
  -out idp-ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/O=MCP-Gateway CI/CN=keycloak" -keyout server.key -out server.csr 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:keycloak,DNS:localhost,IP:127.0.0.1\n' > server.ext
openssl x509 -req -in server.csr -CA idp-ca.pem -CAkey idp-ca.key -CAcreateserial -days 2 -extfile server.ext \
  -out server.crt 2>/dev/null
rm -f server.csr server.ext
chmod 644 ./*
echo "OAuth CI PKI written to $out"
