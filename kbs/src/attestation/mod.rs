// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "coco-as")]
pub mod coco;

pub mod backend;
pub mod config;
pub mod session;

pub use backend::AttestationService;

pub mod error;
pub use error::*;
