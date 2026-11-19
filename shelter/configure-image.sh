#!/bin/bash
set -euo pipefail
src=/usr/share/trustee-shelter
read -r expected_rpm < "$src/rpm-version-arch"
rpm -Uvh "$src"/rpms/*.rpm
rm -rf "$src/rpms"
for package in trustee trustee-frontend; do
    installed_rpm=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$package")
    if [ "$installed_rpm" != "$expected_rpm" ]; then
        printf 'Unexpected installed RPM for %s: expected %s, got %s\n' "$package" "$expected_rpm" "$installed_rpm" >&2
        exit 1
    fi
done
test -s /usr/share/nginx/html/trustee/index.html
# The x86_64 release uses Intel DCAP FFI and reads the distribution QCNL file.
qcnl=/etc/sgx_default_qcnl.conf
grep -q '^PCCS_URL=' "$qcnl"
grep -Fqx 'USE_SECURE_CERT=TRUE' "$qcnl"
sed -i "s|^PCCS_URL=.*|PCCS_URL=$(cat "$src/pccs-url")|" "$qcnl"
# The distribution RPM creates an administrative keypair when installed.
# The exported image contains only the operator's public key.
rm -f /etc/trustee/private.key /etc/trustee/public.pub
install -m 0644 "$src/kbs-config.toml" "$src/as-config.json" /etc/trustee/
gateway=/etc/trustee/gateway.yml
sed -i -e '/^server:/,/^[^[:blank:]#]/s/host: "0\.0\.0\.0"/host: "127.0.0.1"/' \
    -e '/^logging:/,/^[^[:blank:]#]/s/level: "debug"/level: "info"/' "$gateway"
if ! sed -n '/^server:/,/^[^[:blank:]#]/p' "$gateway" | grep -Ex '[[:blank:]]+host: "127\.0\.0\.1"[[:blank:]]*' >/dev/null ||
   ! sed -n '/^logging:/,/^[^[:blank:]#]/p' "$gateway" | grep -Ex '[[:blank:]]+level: "info"[[:blank:]]*' >/dev/null; then
    echo "Unsupported Gateway configuration: expected a loopback listener and info logging" >&2
    exit 1
fi
install -D -m 0600 "$src/policy.rego" /opt/trustee/kbs/policy.rego
install -m 0644 "$src/nginx.conf" /etc/nginx/nginx.conf
install -m 0644 "$src/frontend.conf" /etc/nginx/conf.d/trustee-frontend.conf
install -m 0644 "$src"/trustee-*.acl /etc/nginx/
install -m 0644 "$src/identity.service" /etc/systemd/system/trustee-identity.service
install -m 0644 "$src/chrony.conf" /etc/chrony.conf
for unit in as as-restful kbs nginx trustee-frontend; do
    dropin=/etc/systemd/system/$unit.service.d
    install -d "$dropin"
    printf '%s\n' '[Unit]' 'Requires=trustee-identity.service' 'After=trustee-identity.service' > "$dropin/identity.conf"
done
printf '%s\n' '[Service]' 'Environment=RUST_LOG=info' 'UMask=0077' > /etc/systemd/system/kbs.service.d/privacy.conf
for bin_port in 'as grpc-as 50004' 'as-restful restful-as 50005'; do
    read -r unit bin port <<< "$bin_port"
    printf '%s\n' '[Service]' 'ExecStart=' \
        "ExecStart=/usr/bin/$bin --socket 127.0.0.1:$port --config-file /etc/trustee/as-config.json" \
        > "/etc/systemd/system/$unit.service.d/loopback.conf"
done
systemctl enable chronyd.service trustee.service trustee-frontend.service
