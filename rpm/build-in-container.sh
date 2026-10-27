#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
mkdir -p /work /build/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
tar -xzf /output/source.tar.gz -C /work
cd /work
arch=$(rpm --eval '%{_arch}')
make -C dist create-build-artifacts
cp tmp/* /build/SOURCES/
rpmbuild -ba rpm/trustee.spec --with check --define '_topdir /build' --define 'with_rustup 1'

# Check package metadata and executable dependencies on the actual build platform.
for package in /build/RPMS/"$arch"/*.rpm; do
  test "$(rpm -qp --qf '%{ARCH}' "$package")" = "$arch"
done
dnf install -y /build/RPMS/"$arch"/trustee-[0-9]*.rpm /build/RPMS/"$arch"/attestation-challenge-client-*.rpm
kbs --help >/dev/null
restful-as --help >/dev/null
grpc-as --help >/dev/null
attestation-challenge-client --help >/dev/null
file /usr/bin/kbs /usr/bin/restful-as /usr/bin/grpc-as
mkdir -p /output/RPMS /output/SRPMS
cp -a /build/RPMS/. /output/RPMS/
cp -a /build/SRPMS/. /output/SRPMS/
