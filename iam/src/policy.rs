//! Lightweight policy evaluation helpers.

use serde_json::{Map, Value};

use crate::models::{Condition, ConditionOperator, Effect, PolicyDocument};

/// Evaluate a policy document for the supplied action/resource/context triple.
pub fn evaluate_policy(
    policy: &PolicyDocument,
    action: &str,
    resource: &str,
    context: &Map<String, Value>,
) -> bool {
    let mut allowed = false;
    for statement in &policy.statements {
        if !action_matches(&statement.actions, action) {
            continue;
        }
        if !resource_matches(&statement.resources, resource) {
            continue;
        }
        if !conditions_match(&statement.conditions, context) {
            continue;
        }
        match statement.effect {
            Effect::Deny => return false,
            Effect::Allow => allowed = true,
        }
    }
    allowed
}

fn action_matches(patterns: &[String], action: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| wildcard_match(pattern, action))
}

fn resource_matches(patterns: &[String], resource: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| wildcard_match(pattern, resource))
}

fn conditions_match(conditions: &[Condition], context: &Map<String, Value>) -> bool {
    for condition in conditions {
        let actual = lookup_value(context, &condition.key);
        let matches = match condition.operator {
            ConditionOperator::StringEquals => actual
                .and_then(Value::as_str)
                .map(|value| condition.values.iter().any(|candidate| candidate == value))
                .unwrap_or(false),
            ConditionOperator::StringLike => match actual.and_then(Value::as_str) {
                Some(value) => condition
                    .values
                    .iter()
                    .any(|pattern| wildcard_match(pattern, value)),
                None => false,
            },
            ConditionOperator::Bool => match actual {
                Some(Value::Bool(b)) => condition
                    .values
                    .iter()
                    .filter_map(|candidate| candidate.parse::<bool>().ok())
                    .any(|expected| expected == *b),
                _ => false,
            },
        };

        if !matches {
            return false;
        }
    }
    true
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let mut remainder = value;
    let mut parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .peekable();

    if !pattern.starts_with('*') {
        if let Some(prefix) = parts.next() {
            if !remainder.starts_with(prefix) {
                return false;
            }
            remainder = &remainder[prefix.len()..];
        }
    }

    while let Some(part) = parts.next() {
        if parts.peek().is_none() && !pattern.ends_with('*') {
            return remainder.ends_with(part);
        }
        if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
        } else {
            return false;
        }
    }

    pattern.ends_with('*') || remainder.is_empty()
}

fn lookup_value<'a>(root: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    let mut current: Option<&Value> = None;
    for (index, segment) in key.split('.').enumerate() {
        let next = if index == 0 {
            root.get(segment)?
        } else {
            match current? {
                Value::Object(map) => map.get(segment)?,
                _ => return None,
            }
        };
        current = Some(next);
    }
    current
}
