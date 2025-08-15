#![allow(missing_docs)]

// extern crate tonic_build;

use anyhow::Result;

fn main() -> Result<()> {
    tonic_build::compile_protos(
        "./src/plugins/aliyun/client/client_key_client/protobuf/dkms_api.proto",
    )?;
    Ok(())
}