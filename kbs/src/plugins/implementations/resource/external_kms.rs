// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{anyhow, bail, Result};
use derivative::Derivative;
use libloading::Library;
use log::{info, warn};
use serde::Deserialize;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::Mutex;

type InitFn = unsafe extern "C" fn() -> c_int;
type GetSecretFn =
    unsafe extern "C" fn(*const c_char, *mut u8, *mut c_uint, *mut c_char, c_uint) -> c_int;
type ReleaseFn = unsafe extern "C" fn();

const DEFAULT_LIBRARY_PATH: &str = "/opt/trustee/kbs/libkms_provider.so";
const DEFAULT_INITIAL_BUFFER_SIZE: u32 = 4096;
const DEFAULT_MAX_BUFFER_SIZE: u32 = 1024 * 1024;
const DEFAULT_ERROR_BUFFER_SIZE: u32 = 1024;

#[derive(Derivative, Deserialize, Clone, PartialEq)]
#[derivative(Debug)]
pub struct ExternalKmsBackendConfig {
    #[serde(default = "default_library_path")]
    pub library_path: String,
    #[serde(default = "default_initial_buffer_size")]
    pub initial_buffer_size: u32,
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: u32,
    #[serde(default = "default_error_buffer_size")]
    pub error_buffer_size: u32,
}

fn default_library_path() -> String {
    DEFAULT_LIBRARY_PATH.to_string()
}

fn default_initial_buffer_size() -> u32 {
    DEFAULT_INITIAL_BUFFER_SIZE
}

fn default_max_buffer_size() -> u32 {
    DEFAULT_MAX_BUFFER_SIZE
}

fn default_error_buffer_size() -> u32 {
    DEFAULT_ERROR_BUFFER_SIZE
}

pub struct ExternalKmsBackend {
    _library: Library,
    init: InitFn,
    get_secret_data: GetSecretFn,
    release: ReleaseFn,
    initial_buffer_size: u32,
    max_buffer_size: u32,
    error_buffer_size: u32,
    call_lock: Mutex<()>,
}

impl ExternalKmsBackend {
    pub fn new(config: &ExternalKmsBackendConfig) -> Result<Self> {
        if config.initial_buffer_size == 0 {
            bail!("initial_buffer_size must be greater than 0");
        }
        if config.max_buffer_size < config.initial_buffer_size {
            bail!("max_buffer_size must be >= initial_buffer_size");
        }
        if config.error_buffer_size == 0 {
            bail!("error_buffer_size must be greater than 0");
        }

        let library = unsafe { Library::new(&config.library_path) }
            .map_err(|e| anyhow!("load external KMS library {}: {e}", config.library_path))?;

        let init = unsafe { *library.get::<InitFn>(b"kms_provider_init")? };
        let get_secret_data =
            unsafe { *library.get::<GetSecretFn>(b"kms_provider_get_secret_data")? };
        let release = unsafe { *library.get::<ReleaseFn>(b"kms_provider_release")? };

        let backend = Self {
            _library: library,
            init,
            get_secret_data,
            release,
            initial_buffer_size: config.initial_buffer_size,
            max_buffer_size: config.max_buffer_size,
            error_buffer_size: config.error_buffer_size,
            call_lock: Mutex::new(()),
        };

        backend
            .initialize()
            .map_err(|e| anyhow!("initialize external KMS provider: {e}"))?;

        Ok(backend)
    }

    fn initialize(&self) -> Result<()> {
        let _guard = self
            .call_lock
            .lock()
            .map_err(|e| anyhow!("external KMS provider lock poisoned: {e}"))?;
        let ret = unsafe { (self.init)() };
        if ret != 0 {
            bail!("kms_provider_init failed with code {}", ret);
        }
        Ok(())
    }

    fn fetch_secret(&self, secret_name: &str) -> Result<Vec<u8>> {
        let _guard = self
            .call_lock
            .lock()
            .map_err(|e| anyhow!("external KMS provider lock poisoned: {e}"))?;
        let name = CString::new(secret_name)
            .map_err(|e| anyhow!("secret name contains null bytes: {e}"))?;

        let mut buffer = vec![0u8; self.initial_buffer_size as usize];
        let mut error_buffer = vec![0u8; self.error_buffer_size as usize];

        for _ in 0..3 {
            let mut buffer_len = buffer.len() as c_uint;
            let ret = unsafe {
                (self.get_secret_data)(
                    name.as_ptr(),
                    buffer.as_mut_ptr(),
                    &mut buffer_len,
                    error_buffer.as_mut_ptr() as *mut c_char,
                    self.error_buffer_size,
                )
            };
            if let Some(last) = error_buffer.last_mut() {
                *last = 0;
            }

            if ret == 0 {
                let actual_len = buffer_len as usize;
                if actual_len > buffer.len() {
                    bail!(
                        "kms_provider_get_secret_data returned length {} larger than buffer",
                        actual_len
                    );
                }
                return Ok(buffer[..actual_len].to_vec());
            }

            let required_len = buffer_len as usize;
            if required_len > buffer.len() {
                if required_len as u32 > self.max_buffer_size {
                    bail!(
                        "required secret buffer size {} exceeds max_buffer_size {}",
                        required_len,
                        self.max_buffer_size
                    );
                }
                buffer.resize(required_len, 0u8);
                continue;
            }

            let error_message = unsafe {
                CStr::from_ptr(error_buffer.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .trim()
                    .to_string()
            };
            if error_message.is_empty() {
                bail!("kms_provider_get_secret_data failed with code {}", ret);
            }
            bail!("kms_provider_get_secret_data failed: {}", error_message);
        }

        bail!("kms_provider_get_secret_data failed after retries");
    }
}

impl Drop for ExternalKmsBackend {
    fn drop(&mut self) {
        let _guard = match self.call_lock.lock() {
            Ok(guard) => guard,
            Err(e) => {
                warn!("external KMS provider lock poisoned during drop: {e}");
                return;
            }
        };
        unsafe {
            (self.release)();
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for ExternalKmsBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use external KMS backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = resource_desc.resource_tag;
        self.fetch_secret(&name)
            .map_err(|e| anyhow!("failed to get resource from external KMS: {e}"))
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        bail!("external KMS backend does not support write")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("external KMS backend does not support delete")
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        bail!("external KMS backend does not support list")
    }
}
