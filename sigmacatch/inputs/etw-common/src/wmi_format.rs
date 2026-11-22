// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `Microsoft-Windows-WMI-Activity` → Sysmon EID 19/20/21.
//!
//! The provider's `5858` record carries a single free-form `Operation` string:
//!
//! ```text
//! Start IWbemServices::PutInstance - root\subscription : __EventFilter.Name="probe"
//! ```
//!
//! which is enough to tell *which* subscription object was touched and what
//! its name is — the two fields the `wmi_event` rules key on. The query text
//! and the consumer command line are not in the record, so they stay absent
//! rather than being guessed.
//!
//! Classification follows Sysmon: `__EventFilter` → 19, any `*EventConsumer`
//! → 20, `__FilterToConsumerBinding` → 21.

/// What a `5858` record says happened.
#[derive(Debug, PartialEq, Eq)]
pub struct WmiOperation {
    /// `PutInstance`, `DeleteInstance`, `ExecMethod`, ...
    pub method: String,
    /// Namespace the operation ran in (`root\subscription`).
    pub namespace: String,
    /// Class of the object (`__EventFilter`).
    pub class: String,
    /// `Name="..."` from the object path, when the record carries one.
    pub name: Option<String>,
    /// The object path part after the class, for the binding members.
    pub target: String,
}

impl WmiOperation {
    /// Sysmon event id and `EventType` for this operation.
    pub fn classification(&self) -> Option<(u16, &'static str)> {
        let created = !self.method.contains("Delete");
        if self.class.eq_ignore_ascii_case("__EventFilter") {
            return Some((
                19,
                if created {
                    "WmiFilterCreated"
                } else {
                    "WmiFilterDeleted"
                },
            ));
        }
        if self.class.eq_ignore_ascii_case("__FilterToConsumerBinding") {
            return Some((
                21,
                if created {
                    "WmiBindingCreated"
                } else {
                    "WmiBindingDeleted"
                },
            ));
        }
        if self.class.to_ascii_lowercase().ends_with("eventconsumer") {
            return Some((
                20,
                if created {
                    "WmiConsumerCreated"
                } else {
                    "WmiConsumerDeleted"
                },
            ));
        }
        None
    }
}

/// Extract the `Consumer="..."` and `Filter="..."` members of a binding path.
///
/// Sysmon renders these two fields exactly as the WMI object path spells them
/// (`CommandLineEventConsumer.Name="x"`), so the quoted value is what is kept.
pub fn binding_parts(target: &str) -> (Option<String>, Option<String>) {
    (
        quoted_member(target, "Consumer"),
        quoted_member(target, "Filter"),
    )
}

/// Value of `prefix="..."`, with `\"` unescaped.
fn quoted_member(target: &str, prefix: &str) -> Option<String> {
    let start = target.find(&format!("{prefix}=\""))? + prefix.len() + 2;
    let mut out = String::new();
    let mut chars = target[start..].chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                out.push('"');
                chars.next();
            }
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

/// Parse the `Operation` string of a `5858` record.
///
/// Returns `None` when the string does not have the shape above, which is the
/// case for the provider's other operations (queries, method calls).
pub fn parse_operation(operation: &str) -> Option<WmiOperation> {
    let (_, rest) = operation.split_once("::")?;
    let (method, rest) = rest.split_once(" - ")?;
    let (namespace, target) = rest.split_once(" : ")?;
    let (class, _) = target.split_once('.').unwrap_or((target, ""));
    let class = class.trim();
    if class.is_empty() {
        return None;
    }
    Some(WmiOperation {
        method: method.trim().to_string(),
        namespace: namespace.trim().to_string(),
        class: class.to_string(),
        name: extract_name(target),
        target: target.to_string(),
    })
}

/// `Name="probe"` → `probe`, from anywhere in the object path.
fn extract_name(target: &str) -> Option<String> {
    let start = target.find("Name=\"")? + "Name=\"".len();
    let rest = &target[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filter_put_is_event_19() {
        let op = parse_operation(
            r#"Start IWbemServices::PutInstance - root\subscription : __EventFilter.Name="probe""#,
        )
        .expect("operation parses");
        assert_eq!(op.method, "PutInstance");
        assert_eq!(op.namespace, r"root\subscription");
        assert_eq!(op.class, "__EventFilter");
        assert_eq!(op.name.as_deref(), Some("probe"));
        assert_eq!(op.classification(), Some((19, "WmiFilterCreated")));
    }

    #[test]
    fn a_consumer_put_is_event_20_whatever_its_flavour() {
        for class in [
            "CommandLineEventConsumer",
            "ActiveScriptEventConsumer",
            "LogFileEventConsumer",
        ] {
            let op = parse_operation(&format!(
                r#"Start IWbemServices::PutInstance - root\subscription : {class}.Name="c""#
            ))
            .expect("operation parses");
            assert_eq!(op.classification(), Some((20, "WmiConsumerCreated")));
        }
    }

    #[test]
    fn a_binding_is_event_21_even_with_a_quoted_name_inside() {
        let op = parse_operation(
            r#"Start IWbemServices::PutInstance - root\subscription : __FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"c\"",Filter="""#,
        )
        .expect("operation parses");
        assert_eq!(op.class, "__FilterToConsumerBinding");
        assert_eq!(op.classification(), Some((21, "WmiBindingCreated")));
    }

    #[test]
    fn a_delete_is_reported_as_deleted() {
        let op = parse_operation(
            r#"Start IWbemServices::DeleteInstance - root\subscription : __EventFilter.Name="probe""#,
        )
        .expect("operation parses");
        assert_eq!(op.classification(), Some((19, "WmiFilterDeleted")));
    }

    #[test]
    fn a_binding_exposes_its_consumer_and_filter() {
        let target = r#"__FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"probe-consumer\"",Filter="__EventFilter.Name=\"probe-filter\"""#;
        let (consumer, filter) = binding_parts(target);
        assert_eq!(
            consumer.as_deref(),
            Some(r#"CommandLineEventConsumer.Name="probe-consumer""#)
        );
        assert_eq!(
            filter.as_deref(),
            Some(r#"__EventFilter.Name="probe-filter""#)
        );
    }

    #[test]
    fn unrelated_operations_are_ignored() {
        assert_eq!(
            parse_operation("Start IWbemServices::ExecQuery - root\\cimv2"),
            None
        );
        assert_eq!(parse_operation("garbage"), None);
    }
}
