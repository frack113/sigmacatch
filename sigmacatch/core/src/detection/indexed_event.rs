// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! [`IndexedEvent`]: a detection-view event with a dotted-path index.
//!
//! rsigma-eval's `JsonEvent::get_field` resolves a dotted path
//! (`Event.EventData.Image`) by parsing it and walking the nested JSON, with
//! two small allocations per probe. The SigmaHQ Windows pipelines map about
//! 280 fields to such paths, so that parse dominates evaluation.
//!
//! `IndexedEvent` borrows the nested value (no copy of the JSON) and adds a
//! `path -> &Value` map built once per event, so a probe is one hash lookup.
//! Everything the index cannot answer exactly (arrays, bracket or escaped
//! paths, keys that contain a dot) falls back to `JsonEvent`, so lookups
//! return the same value as before.

use std::borrow::Cow;
use std::collections::HashMap;

use rsigma_eval::event::{Event as RsigmaEvent, EventValue, JsonEvent};
use serde_json::Value;

/// Detection-view event with a precomputed dotted-path index.
pub(crate) struct IndexedEvent<'a> {
    inner: JsonEvent<'a>,
    /// Every object-only path of the event (intermediate objects included).
    paths: HashMap<String, &'a Value>,
    /// True when a miss in `paths` is not proof of absence: the event holds an
    /// array, a key containing `.`, `[` or `\`, or its root is not an object.
    fallback: bool,
}

impl<'a> IndexedEvent<'a> {
    pub(crate) fn new(root: &'a Value) -> Self {
        let mut paths = HashMap::new();
        let mut fallback = false;
        match root.as_object() {
            Some(map) => {
                let mut path = String::new();
                for (key, value) in map {
                    // Root keys are looked up verbatim, like `JsonEvent` does.
                    paths.insert(key.clone(), value);
                    match value {
                        Value::Object(_) | Value::Array(_) if !is_plain_key(key) => {
                            fallback = true;
                        }
                        Value::Array(_) => fallback = true,
                        Value::Object(_) => {
                            path.clear();
                            path.push_str(key);
                            index_children(&mut path, value, &mut paths, &mut fallback);
                        }
                        _ => {}
                    }
                }
            }
            None => fallback = true,
        }
        Self {
            inner: JsonEvent::borrow(root),
            paths,
            fallback,
        }
    }
}

/// A key that can take part in a synthesized dotted path unambiguously.
fn is_plain_key(key: &str) -> bool {
    !key.contains(['.', '[', '\\'])
}

/// Index the children of the object `value`, which lives at `path`.
fn index_children<'a>(
    path: &mut String,
    value: &'a Value,
    paths: &mut HashMap<String, &'a Value>,
    fallback: &mut bool,
) {
    let Value::Object(map) = value else {
        return;
    };
    for (key, child) in map {
        if !is_plain_key(key) {
            *fallback = true;
            continue;
        }
        let mark = path.len();
        path.push('.');
        path.push_str(key);
        // A root key that literally equals this path keeps priority.
        paths.entry(path.clone()).or_insert(child);
        match child {
            Value::Object(_) => index_children(path, child, paths, fallback),
            Value::Array(_) => *fallback = true,
            _ => {}
        }
        path.truncate(mark);
    }
}

impl RsigmaEvent for IndexedEvent<'_> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        if let Some(value) = self.paths.get(path) {
            return Some(EventValue::from(*value));
        }
        if !self.fallback && !path.contains(['[', '\\']) {
            // Object-only event: a path that is not indexed does not exist.
            return None;
        }
        self.inner.get_field(path)
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.inner.any_string_value(pred)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.inner.all_string_values()
    }

    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        self.inner.visit_string_values(visit);
    }

    fn to_json(&self) -> Value {
        self.inner.to_json()
    }

    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        self.inner.field_keys()
    }

    fn top_level_keys(&self) -> Option<Vec<Cow<'_, str>>> {
        self.inner.top_level_keys()
    }

    fn visit_top_level_keys(&self, visit: &mut dyn FnMut(&str)) -> bool {
        self.inner.visit_top_level_keys(visit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every probe returns exactly what `JsonEvent` returns.
    fn assert_same(value: &Value, probes: &[&str]) {
        let plain = JsonEvent::borrow(value);
        let indexed = IndexedEvent::new(value);
        for probe in probes {
            let a = plain.get_field(probe).map(|v| v.to_json());
            let b = indexed.get_field(probe).map(|v| v.to_json());
            assert_eq!(a, b, "probe {probe:?} on {value}");
        }
    }

    #[test]
    fn object_only_event_matches_json_event() {
        let v = json!({
            "product": "windows",
            "service": "sysmon",
            "Event": {
                "System": {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
                "EventData": {"Image": "C:\\a.exe", "CommandLine": "x y", "Empty": null}
            }
        });
        assert_same(
            &v,
            &[
                "product",
                "Event",
                "Event.System",
                "Event.System.EventID",
                "Event.EventData.Image",
                "Event.EventData.Empty",
                "Event.EventData.Missing",
                "Event.Nope.Image",
                "Nope",
                "Nope.Deeper",
                "Event.EventData.Image.Deeper",
                "",
                ".",
            ],
        );
    }

    #[test]
    fn arrays_brackets_and_dotted_keys_fall_back() {
        let v = json!({
            "Event": {
                "EventData": {
                    "Data": [{"Name": "a"}, {"Name": "b"}],
                    "a.b": "dotted",
                    "Plain": "p"
                }
            },
            "x.y": {"z": 1}
        });
        assert_same(
            &v,
            &[
                "Event.EventData.Data",
                "Event.EventData.Data.Name",
                "Event.EventData.Data[0].Name",
                "Event.EventData.Data[-1].Name",
                "Event.EventData.a.b",
                "Event.EventData.Plain",
                "x.y",
                "x.y.z",
                "Event.EventData.Data[0]\\.Name",
                "Event.EventData.Missing",
            ],
        );
    }

    #[test]
    fn root_literal_dotted_key_wins_over_nested_path() {
        let v = json!({"a": {"b": "nested"}, "a.b": "flat"});
        assert_same(&v, &["a.b", "a", "a.c"]);
    }

    #[test]
    fn non_object_root_falls_back() {
        let v = json!([{"a": 1}]);
        assert_same(&v, &["a", "0", "[0].a"]);
    }

    #[test]
    fn keyword_and_shape_accessors_delegate() {
        let v = json!({"Event": {"EventData": {"Image": "needle"}}, "product": "windows"});
        let plain = JsonEvent::borrow(&v);
        let indexed = IndexedEvent::new(&v);
        assert!(indexed.any_string_value(&|s| s == "needle"));
        assert_eq!(plain.all_string_values(), indexed.all_string_values());
        assert_eq!(plain.top_level_keys(), indexed.top_level_keys());
        assert_eq!(plain.field_keys(), indexed.field_keys());
    }
}
