// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Pre-Processor of RVPS

use std::collections::HashMap;

use anyhow::*;

use super::Message;

/// A Ware loaded in Pre-Processor will process all the messages passing
/// through the Pre-Processor. A series of Wares organized in order can
/// process all the messages in need before they are consumed by the
/// Extractors.
pub trait Ware {
    fn handle(
        &self,
        message: &mut Message,
        context: &mut HashMap<String, String>,
        next: Next<'_>,
    ) -> Result<()>;
}

/// Next encapsulates the remaining ware chain to run in [`Ware::handle`]. You can
/// forward the task down the chain with [`run`].
///
/// [`Ware::handle`]: Ware::handle
/// [`run`]: Self::run
#[derive(Clone)]
pub struct Next<'a> {
    wares: &'a [Box<dyn Ware + Send + Sync>],
}

impl<'a> Next<'a> {
    pub(crate) fn new(wares: &'a [Box<dyn Ware + Send + Sync>]) -> Self {
        Next { wares }
    }

    pub fn run(
        mut self,
        message: &mut Message,
        context: &'a mut HashMap<String, String>,
    ) -> Result<()> {
        if let Some((current, rest)) = self.wares.split_first() {
            self.wares = rest;
            current.handle(message, context, self)
        } else {
            Ok(())
        }
    }
}

/// PreProcessor's interfaces
/// `process` processes the given [`Message`], which contains
/// the provenance information and its type. The process
/// can modify the given [`Message`].
pub trait PreProcessorAPI {
    fn process(&self, message: &mut Message) -> Result<()>;
    fn add_ware(&mut self, ware: Box<dyn Ware + Send + Sync>) -> &Self;
}

#[derive(Default)]
pub struct PreProcessor {
    wares: Vec<Box<dyn Ware + Send + Sync>>,
}

impl PreProcessorAPI for PreProcessor {
    fn process(&self, message: &mut Message) -> Result<()> {
        let mut context = HashMap::new();
        let next = Next::new(&self.wares);
        next.run(message, &mut context)
    }

    fn add_ware(&mut self, ware: Box<dyn Ware + Send + Sync>) -> &Self {
        self.wares.push(ware);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Mock ware implementation for testing
    struct MockWare {
        name: String,
        should_fail: bool,
        processed: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Ware for MockWare {
        fn handle(
            &self,
            message: &mut Message,
            context: &mut HashMap<String, String>,
            next: Next<'_>,
        ) -> Result<()> {
            if self.should_fail {
                bail!("Mock ware failure: {}", self.name);
            }

            // Record that this ware was called
            if let Result::Ok(mut processed) = self.processed.lock() {
                processed.push(self.name.clone());
            }

            // Add context entry
            context.insert(format!("ware_{}", self.name), self.name.clone());

            // Continue to next ware
            next.run(message, context)
        }
    }

    #[test]
    fn test_pre_processor_empty() {
        // Create a pre-processor with no wares
        let pre_processor = PreProcessor::default();

        // Create a test message
        let mut message = Message {
            version: "0.1.0".to_string(),
            payload: "test_payload".to_string(),
            r#type: "test_type".to_string(),
        };

        // Process the message
        let result = pre_processor.process(&mut message);
        assert!(result.is_ok(), "Processing should succeed with no wares");
    }

    #[test]
    fn test_pre_processor_add_ware() {
        // Create a pre-processor
        let mut pre_processor = PreProcessor::default();
        let processed = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Add a ware
        pre_processor.add_ware(Box::new(MockWare {
            name: "test_ware".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        // Create a test message
        let mut message = Message {
            version: "0.1.0".to_string(),
            payload: "test_payload".to_string(),
            r#type: "test_type".to_string(),
        };

        // Process the message
        let result = pre_processor.process(&mut message);
        assert!(result.is_ok(), "Processing should succeed with one ware");

        // Check that the ware was called
        let processed = processed.lock().unwrap();
        assert_eq!(processed.len(), 1, "One ware should have been called");
        assert_eq!(
            processed[0], "test_ware",
            "The test_ware should have been called"
        );
    }

    #[test]
    fn test_pre_processor_multiple_wares() {
        // Create a pre-processor
        let mut pre_processor = PreProcessor::default();
        let processed = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Add multiple wares
        pre_processor.add_ware(Box::new(MockWare {
            name: "ware1".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        pre_processor.add_ware(Box::new(MockWare {
            name: "ware2".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        pre_processor.add_ware(Box::new(MockWare {
            name: "ware3".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        // Create a test message
        let mut message = Message {
            version: "0.1.0".to_string(),
            payload: "test_payload".to_string(),
            r#type: "test_type".to_string(),
        };

        // Process the message
        let result = pre_processor.process(&mut message);
        assert!(
            result.is_ok(),
            "Processing should succeed with multiple wares"
        );

        // Check that all wares were called in order
        let processed = processed.lock().unwrap();
        assert_eq!(processed.len(), 3, "Three wares should have been called");
        assert_eq!(processed[0], "ware1", "ware1 should have been called first");
        assert_eq!(
            processed[1], "ware2",
            "ware2 should have been called second"
        );
        assert_eq!(processed[2], "ware3", "ware3 should have been called third");
    }

    #[test]
    fn test_pre_processor_failing_ware() {
        // Create a pre-processor
        let mut pre_processor = PreProcessor::default();
        let processed = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Add a ware that will succeed
        pre_processor.add_ware(Box::new(MockWare {
            name: "success_ware".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        // Add a ware that will fail
        pre_processor.add_ware(Box::new(MockWare {
            name: "failing_ware".to_string(),
            should_fail: true,
            processed: Arc::clone(&processed),
        }));

        // Add another ware that should not be called
        pre_processor.add_ware(Box::new(MockWare {
            name: "not_called_ware".to_string(),
            should_fail: false,
            processed: Arc::clone(&processed),
        }));

        // Create a test message
        let mut message = Message {
            version: "0.1.0".to_string(),
            payload: "test_payload".to_string(),
            r#type: "test_type".to_string(),
        };

        // Process the message
        let result = pre_processor.process(&mut message);
        assert!(
            result.is_err(),
            "Processing should fail with a failing ware"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mock ware failure: failing_ware"),
            "Error message should mention the failing ware"
        );

        // Check that only the first ware was called
        let processed = processed.lock().unwrap();
        assert_eq!(
            processed.len(),
            1,
            "Only the first ware should have been called"
        );
        assert_eq!(
            processed[0], "success_ware",
            "Only success_ware should have been called"
        );
    }
}
