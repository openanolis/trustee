# Native RPM builds

On a Linux **x86_64 or aarch64** host with Git and Docker, check out the desired
release tag or source revision, then run from the repository root:

```sh
sudo bash rpm/build-rpm.sh al8   # Alibaba Cloud Linux 3
sudo bash rpm/build-rpm.sh an23  # Anolis OS 23
```

The scripts build the current tracked source files in a container of the same
architecture. They are native builds, not cross-compilation. Output:
`rpm-output/<distribution>/<architecture>/{RPMS,SRPMS}/`.

`BASE_IMAGE` overrides the distribution image; `OUTPUT_DIR` overrides the output
directory. Cargo caches use Docker volumes scoped by distribution and architecture.
The native RPM workflow builds both architectures and installs/runs the packages.

aarch64 selects `DCAP_BACKEND=rust` in `dist/Makefile` and does not depend on
Intel DCAP shared libraries. It uses the existing `all-verifier-rust` set (TDX,
SNP, CSV, Hygon DCU, system and TPM); this set does **not** include SGX.
x86_64 keeps the existing Intel DCAP backend. To use Rust on x86_64 when building
binaries directly: `make -C dist DCAP_BACKEND=rust`.
Frontend dependencies are prepared natively rather than reusing x86_64 node modules.
The container build also runs the offline SNP signature/certificate regression tests.
