fn main() {
    println!("cargo:rustc-link-lib=python3.11");
    println!("cargo:rustc-link-search=native=/usr/lib");
}
