// Custom channel mappings — loads custom_channels.yaml to extend/override static taxonomy.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

#[derive(Deserialize)]
struct CustomChannels {
    channels: HashMap<String, String>,
}

/// Loads custom channel mappings from custom_channels.yaml.
/// Returns an empty HashMap if the file does not exist.
pub fn load_custom_mapping(path: &Path) -> HashMap<String, String> {
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_yaml::from_str::<CustomChannels>(&content) {
            Ok(custom) => custom.channels,
            Err(e) => {
                warn!("Failed to parse custom_channels.yaml: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            warn!("Failed to read custom_channels.yaml: {}", e);
            HashMap::new()
        }
    }
}

/// Merge custom mapping on top of static mapping.
/// Custom keys win over static keys, non-overlapping static keys are preserved.
pub fn merge_maps(
    static_map: &HashMap<String, String>,
    custom_map: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged = static_map.clone();
    merged.extend(custom_map.clone());
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_custom_mapping_missing_file() {
        let path = Path::new("/nonexistent/custom_channels_nonexistent.yaml");
        let result = load_custom_mapping(path);
        assert!(result.is_empty(), "missing file should return empty HashMap");
    }

    #[test]
    fn test_load_custom_mapping_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom_channels.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "channels:").unwrap();
            writeln!(file, "  'Custom-Channel/Operational': 'custom_service'").unwrap();
            writeln!(file, "  'Another-Channel': 'another_service'").unwrap();
        }
        let result = load_custom_mapping(&path);
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("Custom-Channel/Operational"), Some(&"custom_service".to_string()));
        assert_eq!(result.get("Another-Channel"), Some(&"another_service".to_string()));
    }

    #[test]
    fn test_load_custom_mapping_malformed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom_channels.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "channels: {{invalid yaml content<<<").unwrap();
        }
        let result = load_custom_mapping(&path);
        assert!(result.is_empty(), "malformed YAML should return empty HashMap");
    }

    #[test]
    fn test_merge_maps_custom_wins() {
        let mut static_map = HashMap::new();
        static_map.insert("Security".to_string(), "security".to_string());
        static_map.insert("Sysmon".to_string(), "sysmon".to_string());

        let mut custom_map = HashMap::new();
        custom_map.insert("Security".to_string(), "custom_security".to_string());

        let merged = merge_maps(&static_map, &custom_map);
        assert_eq!(merged.get("Security"), Some(&"custom_security".to_string()));
        assert_eq!(merged.get("Sysmon"), Some(&"sysmon".to_string()));
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_maps_no_overlap() {
        let mut static_map = HashMap::new();
        static_map.insert("Security".to_string(), "security".to_string());

        let mut custom_map = HashMap::new();
        custom_map.insert("Custom/Channel".to_string(), "custom".to_string());

        let merged = merge_maps(&static_map, &custom_map);
        assert_eq!(merged.len(), 2);
        assert!(merged.contains_key("Security"));
        assert!(merged.contains_key("Custom/Channel"));
    }

    #[test]
    fn test_merge_maps_empty_custom() {
        let mut static_map = HashMap::new();
        static_map.insert("Security".to_string(), "security".to_string());

        let custom_map = HashMap::new();
        let merged = merge_maps(&static_map, &custom_map);
        assert_eq!(merged, static_map);
    }
}
