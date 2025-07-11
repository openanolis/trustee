// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Extractors for RVPS.

pub mod extractor_modules;

use anyhow::*;
use std::collections::HashMap;

use self::extractor_modules::{ExtractorInstance, ExtractorModuleList};
use super::{Message, ReferenceValue};

#[derive(Default)]
pub struct Extractors {
    /// A map of provenance types to Extractor initializers
    extractors_module_list: ExtractorModuleList,

    /// A map of provenance types to Extractor instances
    extractors_instance_map: HashMap<String, ExtractorInstance>,
}

impl Extractors {
    /// Register an `Extractor` instance to `Extractors`. The `Extractor` is responsible for
    /// handling specific kind of provenance (as `extractor_name` indicates).
    fn register_instance(&mut self, extractor_name: String, extractor_instance: ExtractorInstance) {
        self.extractors_instance_map
            .insert(extractor_name, extractor_instance);
    }

    /// Instantiate an `Extractor` of given type `extractor_name`. This method will
    /// instantiate an `Extractor` instance and then register it.
    fn instantiate_extractor(&mut self, extractor_name: String) -> Result<()> {
        let instantiate_func = self.extractors_module_list.get_func(&extractor_name)?;
        let extractor_instance = (instantiate_func)();
        self.register_instance(extractor_name, extractor_instance);
        Ok(())
    }

    /// Process the message, by verifying the provenance
    /// and extracting reference values within.
    /// If provenance is valid, return all of the relevant
    /// reference values.
    /// Each ReferenceValue digest is expected to be base64 encoded.
    pub fn process(&mut self, message: Message) -> Result<Vec<ReferenceValue>> {
        let typ = message.r#type;

        if self.extractors_instance_map.get_mut(&typ).is_none() {
            self.instantiate_extractor(typ.clone())?;
        }
        let extractor_instance = self
            .extractors_instance_map
            .get_mut(&typ)
            .ok_or_else(|| anyhow!("The Extractor instance does not existing!"))?;

        extractor_instance.verify_and_extract(&message.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractors::extractor_modules::Extractor;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn test_extractors_process() {
        // 创建一个 Extractors 实例
        let mut extractors = Extractors::default();

        // 创建一个有效的 sample 类型的消息
        let payload = json!({
            "test_artifact": ["hash1", "hash2"]
        });
        let payload_base64 = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        let message = Message {
            version: "0.1.0".to_string(),
            payload: payload_base64,
            r#type: "sample".to_string(),
        };

        // 处理消息
        let result = extractors.process(message);
        assert!(result.is_ok(), "Process should succeed with valid message");

        let reference_values = result.unwrap();
        assert_eq!(
            reference_values.len(),
            1,
            "Should extract one reference value"
        );
        assert_eq!(
            reference_values[0].name, "test_artifact",
            "Reference value name should be test_artifact"
        );
        assert_eq!(
            reference_values[0].hash_value.len(),
            2,
            "Should have two hash values"
        );
        assert_eq!(
            reference_values[0].hash_value[0].alg(),
            "sha384",
            "Algorithm should be sha384"
        );
        assert_eq!(
            reference_values[0].hash_value[0].value(),
            "hash1",
            "First hash value should be hash1"
        );
        assert_eq!(
            reference_values[0].hash_value[1].alg(),
            "sha384",
            "Algorithm should be sha384"
        );
        assert_eq!(
            reference_values[0].hash_value[1].value(),
            "hash2",
            "Second hash value should be hash2"
        );
    }

    #[test]
    fn test_extractors_process_with_invalid_type() {
        // 创建一个 Extractors 实例
        let mut extractors = Extractors::default();

        // 创建一个无效类型的消息
        let payload = json!({
            "test_artifact": ["hash1", "hash2"]
        });
        let payload_base64 = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        let message = Message {
            version: "0.1.0".to_string(),
            payload: payload_base64,
            r#type: "invalid_type".to_string(),
        };

        // 处理消息
        let result = extractors.process(message);
        assert!(result.is_err(), "Process should fail with invalid type");
        assert!(
            result.unwrap_err().to_string().contains("does not support"),
            "Error message should mention unsupported extractor"
        );
    }

    #[test]
    fn test_extractors_process_with_invalid_payload() {
        // 创建一个 Extractors 实例
        let mut extractors = Extractors::default();

        // 创建一个有效类型但无效载荷的消息
        let message = Message {
            version: "0.1.0".to_string(),
            payload: "invalid_base64".to_string(),
            r#type: "sample".to_string(),
        };

        // 处理消息
        let result = extractors.process(message);
        assert!(result.is_err(), "Process should fail with invalid payload");
        assert!(
            result.unwrap_err().to_string().contains("base64 decode"),
            "Error message should mention base64 decode"
        );
    }

    #[test]
    fn test_extractors_register_instance() {
        // 创建一个 Extractors 实例
        let mut extractors = Extractors::default();

        // 创建一个自定义提取器
        struct MockExtractor;
        impl Extractor for MockExtractor {
            fn verify_and_extract(&self, _provenance: &str) -> Result<Vec<ReferenceValue>> {
                Ok(vec![])
            }
        }

        // 注册自定义提取器
        extractors.register_instance("mock".to_string(), Box::new(MockExtractor));

        // 验证提取器已注册
        assert!(
            extractors.extractors_instance_map.contains_key("mock"),
            "Extractor should be registered"
        );
    }
}
