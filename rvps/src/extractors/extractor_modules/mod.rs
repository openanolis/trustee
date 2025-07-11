// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// Add your specific provenance declaration here.

use anyhow::*;
use std::collections::HashMap;

use crate::ReferenceValue;

#[cfg(feature = "in-toto")]
pub mod in_toto;

pub mod sample;

/// Extractor is a standard interface that all provenance extractors
/// need to implement. Here reference_value can be modified in the
/// handler, added any field if needed.
pub trait Extractor {
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>>;
}

pub type ExtractorInstance = Box<dyn Extractor + Sync + Send>;
type ExtractorInstantiateFunc = Box<dyn Fn() -> ExtractorInstance + Send + Sync>;

pub struct ExtractorModuleList {
    mod_list: HashMap<String, ExtractorInstantiateFunc>,
}

impl Default for ExtractorModuleList {
    fn default() -> ExtractorModuleList {
        // TODO: when new extractor is added, change mod_list
        // to mutable.
        let mut mod_list = HashMap::new();

        {
            let instantiate_func: ExtractorInstantiateFunc =
                Box::new(|| -> ExtractorInstance { Box::<sample::SampleExtractor>::default() });
            mod_list.insert("sample".to_string(), instantiate_func);
        }

        #[cfg(feature = "in-toto")]
        {
            let instantiate_func: ExtractorInstantiateFunc =
                Box::new(|| -> ExtractorInstance { Box::new(in_toto::InTotoExtractor::new()) });
            mod_list.insert("in-toto".to_string(), instantiate_func);
        }

        ExtractorModuleList { mod_list }
    }
}

impl ExtractorModuleList {
    pub fn get_func(&self, extractor_name: &str) -> Result<&ExtractorInstantiateFunc> {
        let instantiate_func: &ExtractorInstantiateFunc =
            self.mod_list.get(extractor_name).ok_or_else(|| {
                anyhow!(
                    "RVPS Extractors does not support the given extractor: {}!",
                    extractor_name
                )
            })?;
        Ok(instantiate_func)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_extractor_module_list_default() {
        let module_list = ExtractorModuleList::default();

        // Check that the sample extractor is registered
        assert!(
            module_list.mod_list.contains_key("sample"),
            "Sample extractor should be registered"
        );

        // Check the number of registered extractors
        #[cfg(feature = "in-toto")]
        {
            assert_eq!(
                module_list.mod_list.len(),
                2,
                "Should have 2 extractors with in-toto feature"
            );
            assert!(
                module_list.mod_list.contains_key("in-toto"),
                "in-toto extractor should be registered"
            );
        }

        #[cfg(not(feature = "in-toto"))]
        {
            assert_eq!(
                module_list.mod_list.len(),
                1,
                "Should have 1 extractor without in-toto feature"
            );
        }
    }

    #[test]
    fn test_get_func_existing() {
        let module_list = ExtractorModuleList::default();

        // Get the sample extractor function
        let result = module_list.get_func("sample");
        assert!(
            result.is_ok(),
            "Should successfully get sample extractor function"
        );

        // Instantiate the extractor
        let instantiate_func = result.unwrap();
        let extractor = (instantiate_func)();

        // Verify it's a valid extractor by calling a method
        let verify_result = extractor.verify_and_extract("invalid");
        // We don't care about the result, just that it doesn't panic
        assert!(verify_result.is_err(), "Should fail with invalid input");
    }

    #[test]
    fn test_get_func_nonexistent() {
        let module_list = ExtractorModuleList::default();

        // Try to get a nonexistent extractor function
        let result = module_list.get_func("nonexistent");
        assert!(
            result.is_err(),
            "Should fail to get nonexistent extractor function"
        );
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("does not support"),
            "Error message should mention unsupported extractor"
        );
    }

    // Test custom extractor implementation
    struct TestExtractor;

    impl Extractor for TestExtractor {
        fn verify_and_extract(&self, _provenance: &str) -> Result<Vec<ReferenceValue>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_custom_extractor() {
        // Create a custom extractor
        let extractor = TestExtractor;

        // Test the verify_and_extract method
        let result = extractor.verify_and_extract("test");
        assert!(result.is_ok(), "Custom extractor should succeed");
        assert!(
            result.unwrap().is_empty(),
            "Custom extractor should return empty vector"
        );
    }
}
