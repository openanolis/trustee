%define alinux_release 1
%global config_dir /etc/trustee
%global debug_package %{nil}
%global __brp_mangle_shebangs %{nil}

Name:           trustee
Version:        1.7.7
Release:	    %{alinux_release}%{?dist}
Summary:        Daemon services for attestation and secret distribution
Group:          Applications/System
BuildArch:      x86_64

License:	Apache-2.0
URL: 		  https://github.com/openanolis/trustee
Source0:  trustee-%{version}.tar.gz
Source1:	vendor.tar.gz
Source2: 	config.toml
Source3:  go-vendor.tar.gz
Source4:  frontend_node_modules.tar.gz
Source5:  challenge-ra-policy.rego

Requires: openssl tzdata sqlite-libs

BuildRequires:  cargo clang perl protobuf-devel git libtdx-attest-devel libgudev-devel openssl-devel tpm2-tss tpm2-tss-devel libsgx-dcap-quote-verify-devel libsgx-dcap-quote-verify libsgx-headers
BuildRequires:  ca-certificates gcc golang

%description
Trustee are daemon services for attestation and secret distribution.

%package -n attestation-challenge-client
Summary:        Challenge-mode remote attestation one-shot CLI

%description -n attestation-challenge-client
A standalone CLI that fetches evidence from attestation-agent and verifies it locally using the attestation-service library, producing an EAR token.

%package -n trustee-frontend
Summary:        Web frontend for trustee services
Requires:       trustee = %{version}-%{release}
Requires:       nginx >= 1.16
BuildRequires:  nodejs >= 16.0.0 npm

%description -n trustee-frontend
Web frontend for trustee attestation and secret distribution services.
This package provides a web-based interface for managing and monitoring 
trustee services including KBS, AS, RVPS, and Gateway.

%prep
%autosetup -n trustee-%{version}
tar -xvf %{SOURCE1}
sed -i 's/version = 4/version = 3/g' Cargo.lock
mkdir -p .cargo
cp %{SOURCE2} .cargo/
tar -xvf %{SOURCE3} -C trustee-gateway
tar -xvf %{SOURCE4} -C frontend

%build
pushd dist/
make
popd
pushd frontend/
npm run build
popd

%install
pushd dist/
make install BUILDROOT=%{buildroot} PREFIX=%{_prefix} CONFIG_DIR=%{config_dir}
popd

pushd dist/
make install-frontend BUILDROOT=%{buildroot} PREFIX=%{_prefix} CONFIG_DIR=%{config_dir}
popd

# Install default EAR policy for attestation-challenge-client
install -d %{buildroot}/var/lib/attestation/token/ear/policies/opa
install -m 0644 %{SOURCE5} %{buildroot}/var/lib/attestation/token/ear/policies/opa/default.rego

%post
systemctl daemon-reload
openssl genpkey -algorithm ed25519 > /etc/trustee/private.key
openssl pkey -in /etc/trustee/private.key -pubout -out /etc/trustee/public.pub
systemctl start trustee

%post -n trustee-frontend
systemctl enable trustee-frontend
systemctl start trustee-frontend

%preun
if [ $1 == 0 ]; then #uninstall
  systemctl unmask trustee kbs as as-restful rvps
  systemctl stop trustee kbs as as-restful rvps
  systemctl disable trustee kbs as as-restful rvps
  rm -rf /etc/trustee/private.key /etc/trustee/public.pub
fi

%preun -n trustee-frontend
if [ $1 == 0 ]; then #uninstall
    systemctl stop trustee-frontend
    systemctl disable trustee-frontend
fi

%postun
if [ $1 == 0 ]; then #uninstall
  systemctl daemon-reload
  systemctl reset-failed
fi

%postun -n trustee-frontend
if [ $1 == 0 ]; then #uninstall
    rm -f /etc/nginx/conf.d/trustee-frontend.conf
    
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
    fi
    
    systemctl reset-failed trustee-frontend
fi

%files
%{_prefix}/bin/kbs
%{_prefix}/bin/grpc-as
%{_prefix}/bin/restful-as
%{_prefix}/bin/rvps
%{_prefix}/bin/trustee-gateway
%{_prefix}/bin/rvps-tool
%exclude %{_prefix}/bin/attestation-challenge-client
%{config_dir}/kbs-config.toml
%{config_dir}/as-config.json
%{config_dir}/rvps.json
%{config_dir}/gateway.yml
%{_prefix}/lib/systemd/system/kbs.service
%{_prefix}/lib/systemd/system/as.service
%{_prefix}/lib/systemd/system/as-restful.service
%{_prefix}/lib/systemd/system/rvps.service
%{_prefix}/lib/systemd/system/trustee-gateway.service
%{_prefix}/lib/systemd/system/trustee.service
/usr/include/sgx_*
/usr/lib64/lib*
/etc/sgx*

%files -n trustee-frontend
/usr/share/nginx/html/trustee/*
/etc/nginx/conf.d/trustee-frontend.conf
%{_prefix}/lib/systemd/system/trustee-frontend.service
%{_prefix}/bin/trustee-frontend-start

%files -n attestation-challenge-client
%{_prefix}/bin/attestation-challenge-client
/var/lib/attestation/token/ear/policies/opa/default.rego

%changelog
* Wed Jan 7 2026 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.7.7-1
- Release v1.7.6 images and helm-chart by @jialez0 
- Fix repeat kbs-session-id header nits of gateway by @jialez0 
- Gateway: support mysql by @wdsun1008 

* Mon Dec 29 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.7.6-1
- Support skip GPU evidence verification via ENV by @jialez0 in #107
- KBS /resource API: support parse attest token from Attestation header by @jialez0 in #108
- Add RPM release workflow and update Makefile by @1570005763 in #105
- Feat: iml Reference-Value-Distribution-Service (RVDS) by @jialez0 in #109
- RVDS: support ledger eventlog record and ethereumAdapter by @jialez0 in #110
- KBS: support encrypted local fs storage backend by @wdsun1008 in #113
- Challenge RA: impl attestation-oneshot-client by @jialez0 in #114
- Sample verify: support verify ccel and measurement register by @jialez0 in #115
- Add manual trigger support for RPM build workflow with tag name input by @1570005763 in #116
- Challenge RA client: support retrieve reference-value from Rekor by @jialez0 in #118
- slsa provenance: use absolute path as file measurement name by @jialez0 in #119
- Update c-ra client and rvps slsa logic by @jialez0 in #121
- EAR policy: add AI model measurement parse by @jialez0 in #122
- EAR policy: fix tpm measurement algorithm strings by @jialez0 in #123

* Mon Dec 1 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.7.4-1
- Resource Policy: Fix file_system to file-system by @jialez0 in #103

* Tue Nov 4 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.7.3-1
- 
- TPM verifier: Fix parse TPM2B_PUBLIC AK from registrar by @jialez0 in #101
- Release v1.7.0 Image by @jialez0 in #98
- TPM verifier: support keylime registrar for AK endorsement by @jialez0 in #99
- Docs: add reference value computing document by @jialez0 in #100

* Mon Oct 27 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.7.0-1
- AS: support JWT Nonce challenge response by @jialez0 in #91
- Dist: Use EAR token as default token type by @jialez0 in #92
- Fix EAR truste vector parse logic bugs by @jialez0 in #93
- TPM verifier: fix event digests algorithm name by @jialez0 in #94
- Fix event digests algo name and update kbs resource policy by @jialez0 in #95
- Fix AS cargo test failed of ear policy by @jialez0 in #96
- Update documents: add attestation and resource docs by @jialez0 in #97

* Tue Oct 14 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.6.2-1
- add csv policy by @Xynnn007 in #72
- Update helm chart version to 1.6.0 by @jialez0 in #73
- trustee: support proxy by @jiazhang0 in #74
- gateway /audit support return total record count by @jialez0 in #81
- AS: fix csv policy for cryptpilot by @Xynnn007 in #79
- Dockerfile.trustee-gateway: use aliyun mirror to download golang by @jiazhang0 in #78
- Bump actions/checkout from 4 to 5 by @dependabot[bot] in #67
- Ic fix tdx aael by @Xynnn007 in #82
- AS: update TDX ear policy for UEFI eventlog by @Xynnn007 in #83
- AS: fix ear policy for tdx by @Xynnn007 in #85
- Anolis/fix policy with - names by @Xynnn007 in #86
- Optimize HTTP error return details by @jialez0 in #84
- Bug fix: fix ear policy syntax nits by @jialez0 in #87

* Fri Sep 12 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.6.0-2
- Support frontend offline build

* Wed Aug 27 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.6.0-1
- Release v1.5.2 images by @jialez0 in #70
- Protocol rebase to 0.4.0 (support combined attestation) by @jialez0 in #64
- Release v1.6.0 container images by @jialez0 in #71

* Wed Aug 27 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.5.2-1
- doc: update api doc for audit by @wdsun1008 in #61
- Fix kbs-types dependency rev by @jialez0 in #66
- Fix gateway config file path in docker-compose.yml by @jialez0 in #68
- Gateway: support /api/as as /api/attestation-service by @jialez0 in #69

* Tue Jul 29 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.5.1-1
- README: fix components explain by @jialez0 in #58
- Release v1.5.0 images by @jialez0 in #57
- Add Unit tests by @jialez0 in #59
- Gateway: support memory sqlite by @wdsun1008 in #60

* Tue Jul 29 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.5.0-1
- TPM verifier bug fix by @jialez0 in #50
- Dockerfile.frontend: modify nginx config path to consist with RPM by @jialez0 in #51
- Support DELETE method of policy and resources by @jialez0 in #53
- Gateway: add record total number by @wdsun1008 in #54
- Update README.md by @jialez0 in #55
- Update Gateway API Document: Add catalogue by @jialez0 in #56

* Sun Jun 29 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.4.3-1
- TDX verifier: support GPU attestation by @jialez0 in #47
- Frontend: parse json string in claims by @wdsun1008 in #48
- Add trustee Dockerfile by @jialez0 in #49

* Mon Jun 23 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.4.2-1
- Frontend: use noble instead of web crypto by @wdsun1008 in #46

* Mon Jun 16 2025 Weidong Sun <sunweidong.swd@alibaba-inc.com> -1.4.1-1
- Dist: add frontend RPM files by @wdsun1008 in #43
- AS: remove se-verifier to fix Segment Fault in TDX quote verifying by @jialez0 in #44
- TDX Verifier: Support parse CCEL measurements with new format by @jialez0 in #45

* Wed Jun 11 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.4.0-1
- Update RPM makefile and TPM verifier by @jialez0 in #38
- TDX verifier: support parse AA Eventlog by @jialez0 in #39
- Gateway: support AA Instanceinfo by @wdsun1008 in #40
- KBS: Optimize response error HTTP code by @jialez0 in #42

* Sat May 31 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.3.0-1
- Gateway: add claims to attestation audit by @wdsun1008
- Update RPM dist: add policy dir config and intel files by @jialez0
- RPM dist: add Makefile for install by @jialez0
- Gateway: support as restful attestation audit by @wdsun1008
- Fix list resource & health check by @wdsun1008
- RPM dist: fix as-config.json policy dir field name by @jialez0
- Gateway: audit auto cleanup and support https by @wdsun1008

* Wed May 21 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.2.1-1
- Gateway: fix database directory

* Sun May 18 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.2.0-1
- Add trustee gateway service

* Sat May 10 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.1.3-1
- Move bins from /usr/local to /usr

* Thu Apr 3 2025 Jiale Zhang <xinjian.zjl@alibaba-inc.com> -1.1.2-1
- First release