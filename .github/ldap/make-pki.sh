#!/bin/sh
# Throwaway PKI for the LDAP CI job: written to .github/ldap/pki/. Never use these outside CI.
set -eu
out="$(dirname "$0")/pki"
mkdir -p "$out"
cd "$out"

ca() {  # file, CN
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/O=MCP-Gateway CI/CN=$2" \
    -keyout "$1.key" -out "$1.pem" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

ca ldap-ca "Directory CA"
ca other-ca "Untrusted CA"

# The directory's certificate names only "openldap": the network alias "ldap-alias" must fail verification.
openssl req -newkey rsa:2048 -nodes -subj "/O=MCP-Gateway CI/CN=openldap" -keyout server.key -out server.csr 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:openldap\n' > server.ext
openssl x509 -req -in server.csr -CA ldap-ca.pem -CAkey ldap-ca.key -CAcreateserial -days 2 -extfile server.ext \
  -out server.crt 2>/dev/null
rm -f server.csr server.ext
cp ldap-ca.pem ca.crt
# PKCS#3 DH parameters: slapd here is built with GnuTLS, which cannot read the X9.42 output of "-dsaparam".
openssl dhparam -out dhparam.pem 2048 2>/dev/null
chmod 644 ./*
echo "LDAP CI PKI written to $out"
