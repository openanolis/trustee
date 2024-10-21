fn main() {
    println!("cargo:rustc-link-lib=python3.12");
    println!("cargo:rustc-link-search=native=/usr/lib");
}
