#!/bin/bash
set -euo pipefail
umask 077
cd "${STATE_DIRECTORY:-/var/lib/trustee-shelter}"
verify_certificates() {
    openssl verify -purpose sslserver -verify_hostname trustee.internal -CAfile "$1/ca.crt" "$1/server.crt" &&
        openssl verify -purpose sslclient -CAfile "$1/ca.crt" "$1/signer.crt"
}
if [[ ! -d identity ]]; then
    stage=$(mktemp -d .identity.XXXXXXXX)
    trap 'rm -rf -- "$stage"' EXIT
    openssl ecparam -name prime256v1 -genkey -noout -out "$stage/ca.key"
    # Avoid duplicate CA extensions from distribution-wide openssl.cnf defaults.
    cat > "$stage/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ca
[dn]
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign
subjectKeyIdentifier = hash
EOF
    openssl req -new -x509 -sha256 -days 3650 -key "$stage/ca.key" -config "$stage/ca.cnf" \
        -subj '/CN=Trustee TDVM instance root' -out "$stage/ca.crt"
    for purpose in server signer; do
        if [[ $purpose == server ]]; then
            printf '%s\n' 'extendedKeyUsage=serverAuth' \
                'subjectAltName=DNS:trustee.internal,DNS:localhost,IP:127.0.0.1' > "$stage/extensions"
        else
            printf '%s\n' 'extendedKeyUsage=clientAuth' > "$stage/extensions"
        fi
        printf '%s\n' 'keyUsage=critical,digitalSignature' 'basicConstraints=critical,CA:FALSE' >> "$stage/extensions"
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$stage/$purpose.key"
        openssl req -new -key "$stage/$purpose.key" -subj "/CN=trustee-$purpose" -out "$stage/request.csr"
        openssl x509 -req -in "$stage/request.csr" -CA "$stage/ca.crt" -CAkey "$stage/ca.key" \
            -CAcreateserial -days 365 -sha256 -extfile "$stage/extensions" -out "$stage/$purpose.crt"
    done
    verify_certificates "$stage"
    rm "$stage/ca.key" "$stage/ca.cnf" "$stage/extensions" "$stage/request.csr" "$stage/ca.srl"
    if [[ -f /usr/share/trustee-shelter/interop-local-admin ]]; then
        openssl genpkey -algorithm ED25519 -out "$stage/admin.key"
        openssl pkey -in "$stage/admin.key" -pubout -out "$stage/admin.pub"
    else
        cp /usr/share/trustee-shelter/admin.pub "$stage/admin.pub"
    fi
    mv -T "$stage" identity
elif ! verify_certificates identity; then
    echo "Stored Trustee certificates failed verification with the synchronized clock; restore or renew the instance identity." >&2
    exit 1
fi
# Only the public trust anchor goes to the guest serial console.
cat identity/ca.crt
