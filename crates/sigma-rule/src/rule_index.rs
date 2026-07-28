// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `RuleIndex` — map of product → rule IDs for efficient product-scoped rule access.

use sigmacatch_types::Product;
use std::collections::HashMap;

/// Map of product → rule IDs for efficient product-scoped rule access.
#[derive(Debug, Clone, Default)]
pub struct RuleIndex {
    index: HashMap<Product, Vec<String>>,
}

impl RuleIndex {
    /// Create a new empty rule index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rule ID under the given product.
    pub fn add_rule(&mut self, product: Product, rule_id: String) {
        self.index.entry(product).or_default().push(rule_id);
    }

    /// Get all rule IDs for the given product. Returns empty vec if no rules.
    pub fn get(&self, product: &Product) -> &[String] {
        self.index
            .get(product)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Check if there are any rules for the given product.
    pub fn has_rules(&self, product: &Product) -> bool {
        self.index.get(product).is_some_and(|v| !v.is_empty())
    }

    /// Total number of rule entries across all products.
    pub fn len(&self) -> usize {
        self.index.values().map(Vec::len).sum()
    }

    /// Whether there are no rules at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all (product, rule_ids) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Product, &[String])> {
        self.index.iter().map(|(k, v)| (k, v.as_slice()))
    }
}
