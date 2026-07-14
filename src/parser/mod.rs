use roxmltree::Node;
use serde_json::{Map, Value};

#[allow(dead_code)]
pub struct XmlParser;

#[allow(dead_code)]
impl XmlParser {
    pub fn parse(&self, xml: &str) -> Result<Value, XmlParseError> {
        let doc = roxmltree::Document::parse(xml).map_err(|e| XmlParseError {
            message: format!("Failed to parse XML: {}", e),
            xml_truncated: Self::truncate_xml(xml, 1024),
        })?;

        let root = doc.root();
        let mut map = Map::new();

        // Extract System fields
        Self::extract_system(root, &mut map);

        // Extract EventData fields
        Self::extract_event_data(root, &mut map);

        // Extract binary data (Base64)
        Self::extract_binary_data(root, &mut map);

        // Add metadata
        map.insert("_source".into(), Value::String("winevt".to_string()));
        map.insert("_raw_xml".into(), Value::String(xml.to_string()));

        Ok(Value::Object(map))
    }

    fn extract_system(root: Node, map: &mut Map<String, Value>) {
        let system = root.descendants().find(|n| n.tag_name().name() == "System");
        if let Some(system) = system {
            // Extract Provider
            let provider = system
                .descendants()
                .find(|n| n.tag_name().name() == "Provider");
            if let Some(provider) = provider {
                if let Some(name) = provider.attribute("Name") {
                    map.insert("ProviderName".into(), Value::String(name.to_string()));
                }
            }

            // Extract EventID
            let event_id = system
                .descendants()
                .find(|n| n.tag_name().name() == "EventID");
            if let Some(event_id) = event_id {
                if let Some(text) = event_id.text() {
                    map.insert("EventID".into(), Value::String(text.to_string()));
                    if let Ok(id) = text.trim().parse::<u32>() {
                        map.insert("EventID_num".into(), Value::Number(id.into()));
                    }
                }
            }

            // Extract TimeCreated
            let time_created = system
                .descendants()
                .find(|n| n.tag_name().name() == "TimeCreated");
            if let Some(time_created) = time_created {
                if let Some(system_time) = time_created.attribute("SystemTime") {
                    map.insert("TimeCreated".into(), Value::String(system_time.to_string()));
                }
            }

            // Extract Channel — try System direct child first, then root attribute
            let channel = system
                .children()
                .find(|n| n.tag_name().name() == "Channel")
                .and_then(|n| n.text().map(|t| t.to_string()))
                .or_else(|| root.attribute("Channel").map(|s| s.to_string()));
            if let Some(channel) = channel {
                map.insert("Channel".into(), Value::String(channel));
            }

            // Extract EventRecordID
            let event_record_id = system
                .descendants()
                .find(|n| n.tag_name().name() == "EventRecordID");
            if let Some(event_record_id) = event_record_id {
                if let Some(text) = event_record_id.text() {
                    map.insert("EventRecordID".to_string(), Value::String(text.to_string()));
                    if let Ok(id) = text.trim().parse::<u64>() {
                        map.insert("EventRecordID_num".to_string(), Value::Number(id.into()));
                    }
                }
            }

            // Extract Version, Level, Task, Keywords
            for field in &["Version", "Level", "Task", "Opcode", "Keywords"] {
                if let Some(node) = system.descendants().find(|n| n.tag_name().name() == *field) {
                    if let Some(text) = node.text() {
                        map.insert(field.to_string(), Value::String(text.to_string()));
                    }
                }
            }
        }

        // Extract ExecutionInfo
        let execution = root
            .descendants()
            .find(|n| n.tag_name().name() == "Execution");
        if let Some(execution) = execution {
            if let Some(process_id) = execution.attribute("processID") {
                map.insert("ProcessID".into(), Value::String(process_id.to_string()));
            }
            if let Some(thread_id) = execution.attribute("threadID") {
                map.insert("ThreadID".into(), Value::String(thread_id.to_string()));
            }
        }
    }

    fn extract_event_data(root: Node, map: &mut Map<String, Value>) {
        let event_data = root
            .descendants()
            .find(|n| n.tag_name().name() == "EventData");
        if let Some(event_data) = event_data {
            for node in event_data.descendants() {
                if node.tag_name().name() == "Data" {
                    if let Some(name) = node.attribute("Name") {
                        // Check if data is binary (Base64)
                        if let Some(encoding) = node.attribute("Encoding") {
                            if encoding == "base64" || encoding == "base64encode" {
                                continue; // Handled by extract_binary_data
                            }
                        }

                        if let Some(text) = node.text() {
                            map.insert(name.to_string(), Value::String(text.to_string()));
                        }
                    }
                }
            }
        }

        // Also check for UserData section
        let user_data = root
            .descendants()
            .find(|n| n.tag_name().name() == "UserData");
        if let Some(user_data) = user_data {
            for node in user_data.descendants() {
                if node.tag_name().name() == "EventXML" || node.tag_name().name() == "Data" {
                    if let Some(text) = node.text() {
                        if !text.is_empty() {
                            map.insert("_userdata".into(), Value::String(text.to_string()));
                        }
                    }
                }
            }
        }
    }

    fn extract_binary_data(root: Node, map: &mut Map<String, Value>) {
        let event_data = root
            .descendants()
            .find(|n| n.tag_name().name() == "EventData");
        if let Some(event_data) = event_data {
            for node in event_data.descendants() {
                if node.tag_name().name() == "Data" {
                    if let Some(encoding) = node.attribute("Encoding") {
                        if encoding == "base64" || encoding == "base64encode" {
                            if let Some(name) = node.attribute("Name") {
                                if let Some(text) = node.text() {
                                    map.insert(
                                        format!("{}_base64", name),
                                        Value::String(text.to_string()),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn truncate_xml(xml: &str, max_len: usize) -> String {
        if xml.len() <= max_len {
            xml.to_string()
        } else {
            let safe_end = xml.floor_char_boundary(max_len);
            format!("{}... ({} chars total)", &xml[..safe_end], xml.len())
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct XmlParseError {
    pub message: String,
    pub xml_truncated: String,
}

impl std::fmt::Display for XmlParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "XML parse error: {} (truncated: {})",
            self.message, self.xml_truncated
        )
    }
}

impl std::error::Error for XmlParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_xml_short() {
        let xml = "<EventID>1</EventID>";
        let result = XmlParser::truncate_xml(xml, 1024);
        assert_eq!(result, xml);
    }

    #[test]
    fn test_truncate_xml_long() {
        let xml = "a".repeat(2000);
        let result = XmlParser::truncate_xml(&xml, 100);
        assert!(result.starts_with("aaaaa"));
        assert!(result.ends_with(" chars total)"));
        assert!(result.len() < xml.len());
    }

    #[test]
    fn test_parse_sysmon_process() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{...}"/>
                <EventID>1</EventID>
                <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd /c whoami</Data>
                <Data Name="User">DOMAIN\\user</Data>
            </EventData>
        </Event>"#;

        let parser = XmlParser {};
        let result = parser.parse(xml).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("EventID").unwrap(), "1");
        assert_eq!(obj.get("ProviderName").unwrap(), "Microsoft-Windows-Sysmon");
        assert!(obj.get("Image").unwrap().to_string().contains("cmd.exe"));
        assert_eq!(obj.get("CommandLine").unwrap(), "cmd /c whoami");
        assert_eq!(obj.get("_source").unwrap(), "winevt");
        assert!(obj.contains_key("_raw_xml"));
    }

    #[test]
    fn test_parse_security_event() {
        let xml = r#"<Event Channel="Security">
            <System>
                <Provider Name="Security"/>
                <EventID>4688</EventID>
                <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
            </System>
            <EventData>
                <Data Name="SubjectUserName">user</Data>
                <Data Name="NewProcessName">C:\\Windows\\System32\\notepad.exe</Data>
                <Data Name="CommandLine">notepad.exe</Data>
            </EventData>
        </Event>"#;

        let parser = XmlParser {};
        let result = parser.parse(xml).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("EventID").unwrap(), "4688");
        assert!(obj
            .get("NewProcessName")
            .unwrap()
            .to_string()
            .contains("notepad.exe"));
    }

    #[test]
    fn test_parse_base64_data() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Test"/>
                <EventID>100</EventID>
            </System>
            <EventData>
                <Data Name="Hash">base64content==</Data>
                <Data Name="Hash" Encoding="base64">binarydata==</Data>
            </EventData>
        </Event>"#;

        let parser = XmlParser {};
        let result = parser.parse(xml).unwrap();
        let obj = result.as_object().unwrap();

        assert!(obj.contains_key("Hash_base64"));
        assert_eq!(obj.get("Hash_base64").unwrap(), "binarydata==");
    }

    #[test]
    fn test_parse_invalid_xml() {
        let xml = "<invalid><xml";
        let parser = XmlParser {};
        let result = parser.parse(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_real_winevt_xml() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-4C7F-9CFE-9DC9D4AC938D}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-07-11T14:14:56.1622595Z'/><EventRecordID>1788</EventRecordID><Correlation/><Execution ProcessID='3948' ThreadID='4352'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-1A4UQPS</Computer><Security/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-07-11 14:14:56.101</Data><Data Name='ProcessGuid'>{31190795-4fe0-6a52-0e01-000000001700}</Data><Data Name='ProcessId'>7676</Data><Data Name='Image'>C:\Windows\System32\SearchFilterHost.exe</Data></EventData></Event>"#;

        let parser = XmlParser {};
        let result = parser.parse(xml);
        assert!(
            result.is_ok(),
            "Failed to parse real Winevt XML: {:?}",
            result
        );
        let obj = result.unwrap();
        assert_eq!(obj.get("EventID").unwrap(), "1");
        assert_eq!(obj.get("ProviderName").unwrap(), "Microsoft-Windows-Sysmon");
        assert_eq!(
            obj.get("Image").unwrap(),
            "C:\\Windows\\System32\\SearchFilterHost.exe"
        );
    }
}
