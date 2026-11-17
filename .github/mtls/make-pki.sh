#!/bin/sh
# Throwaway PKI for the mTLS CI job: written to .github/mtls/pki/. Never use these outside CI.
set -eu
out="$(dirname "$0")/pki"
mkdir -p "$out/nginx" "$out/upstream"
cd "$out"

ca() {  # file, CN
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/O=MCP-Gateway CI/CN=$2" \
    -keyout "$1.key" -out "$1.pem" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
leaf() {  # file, CA file, CN, extensions (one per line)
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/O=MCP-Gateway CI/CN=$3" \
    -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\n%s\n' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial -days 2 -extfile "$1.ext" \
    -out "$1.pem" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}

# Agents: the CA nginx and the gateway trust, an agent, an agent nobody registered, and an impostor.
ca agent-ca "Agent CA"
ca other-ca "Untrusted CA"
leaf agent agent-ca hr-bot "extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ci.example/agents/hr-bot"
leaf unknown agent-ca stranger "extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ci.example/agents/stranger"
leaf impostor other-ca hr-bot "extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ci.example/agents/hr-bot"

# nginx's own certificate on the agent listener (8443).
ca edge-ca "Edge CA"
leaf edge edge-ca localhost "extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"

# The upstream MCP server requires a client certificate; the gateway presents one.
ca upstream-ca "Upstream server CA"
ca upstream-client-ca "Upstream client CA"
leaf upstream upstream-ca mock-upstream-tls "extendedKeyUsage=serverAuth
subjectAltName=DNS:mock-upstream-tls"
leaf gateway-client upstream-client-ca mcp-gateway "extendedKeyUsage=clientAuth
subjectAltName=DNS:gateway.ci.example"

cp ../../../deploy/mtls/agent-mtls.conf nginx/
cp edge.pem nginx/server.crt
cp edge.key nginx/server.key
cp agent-ca.pem nginx/agent-ca.pem
cp upstream.pem upstream-client-ca.pem upstream/
cp upstream.key upstream/upstream.key
# Containers run as nginx (uid 101) and mgw (uid 10001): CI-only keys are made readable to them.
chmod 644 ./*.pem ./*.key nginx/* upstream/*
echo "PKI written to $out"
