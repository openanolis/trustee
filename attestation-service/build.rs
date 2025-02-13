use std::process::exit;

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    tonic_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;

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

    Ok(())
}

fn main() -> shadow_rs::SdResult<()> {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {e}");
        exit(1);
    }

    shadow_rs::new()
}
