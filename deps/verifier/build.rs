fn main() {
    let python_version = std::env::var("PYTHON_VERSION").unwrap_or_else(|_| "3.12".to_string());

    match python_version.as_str() {
        "3.8" => {
            println!("cargo:rustc-link-lib=python3.8");
        }
        "3.12" => {
            println!("cargo:rustc-link-lib=python3.12");
        }
        _ => {
            println!(
                "cargo:warning=Unsupported Python version: {}",
                python_version
            );
            println!("cargo:warning=Defaulting to Python 3.12");
            println!("cargo:rustc-link-lib=python3.12");
        }
    }

    println!("cargo:rustc-link-search=native=/usr/lib");
}
