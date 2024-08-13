use std::process::exit;

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    tonic_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;

    println!("cargo:rustc-link-lib=python3.11");
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
