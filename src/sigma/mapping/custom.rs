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

}
