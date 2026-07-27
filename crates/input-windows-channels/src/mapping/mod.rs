// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

pub mod channel_list;

use sigmacatch_types::{
    CHANNEL_EVENT_TO_CATEGORY, CHANNEL_EVENT_TO_SUBCATEGORY, CHANNEL_TO_SERVICE,
};
use std::collections::HashMap;

/// Build a reverse map: service (or service:category) → Vec<ChannelTarget>.
#[derive(Debug, Clone)]
pub struct ChannelTarget {
    pub channel: String,
    pub event_ids: Option<Vec<u32>>,
}

pub fn build_logsource_to_channels(
    custom_map: &HashMap<String, String>,
) -> HashMap<String, Vec<ChannelTarget>> {
    let mut service_targets: HashMap<String, Vec<String>> = HashMap::new();
    let mut category_targets: HashMap<String, Vec<(String, Vec<u32>)>> = HashMap::new();

    for (channel, service) in &CHANNEL_TO_SERVICE {
        service_targets
            .entry(service.to_string())
            .or_default()
            .push(channel.to_string());
    }

    for (channel, service) in custom_map {
        service_targets
            .entry(service.clone())
            .or_default()
            .push(channel.clone());
    }

    for (key, category) in &CHANNEL_EVENT_TO_CATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
                    let cat_key = format!("{}:{}", service, category);
                    category_targets
                        .entry(cat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                }
            }
        }
    }

    for (key, subcat) in &CHANNEL_EVENT_TO_SUBCATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
                    let subcat_key = format!("{}:{}", service, subcat);
                    let parent_key = format!(
                        "{}:{}",
                        service,
                        CHANNEL_EVENT_TO_CATEGORY
                            .get(key)
                            .copied()
                            .unwrap_or_default()
                    );
                    category_targets
                        .entry(subcat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                    if let Some(parent_targets) = category_targets.get_mut(&parent_key) {
                        parent_targets.push((channel.to_string(), vec![eid]));
                    }
                }
            }
        }
    }

    let mut merged: HashMap<String, Vec<ChannelTarget>> = HashMap::new();

    for (service, channels) in service_targets {
        let mut targets: Vec<ChannelTarget> = channels
            .into_iter()
            .map(|channel| ChannelTarget {
                channel,
                event_ids: None,
            })
            .collect();
        targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(service, targets);
    }

    for (cat_key, targets) in category_targets {
        let existing: Vec<ChannelTarget> = merged.remove(&cat_key).unwrap_or_default();
        let mut by_channel: HashMap<String, Vec<u32>> = HashMap::new();
        for (channel, eids) in targets {
            by_channel.entry(channel).or_default().extend(eids);
        }
        let mut merged_targets: Vec<ChannelTarget> = by_channel
            .into_iter()
            .map(|(channel, mut eids)| {
                eids.sort();
                eids.dedup();
                ChannelTarget {
                    channel,
                    event_ids: Some(eids),
                }
            })
            .collect();
        merged_targets.extend(existing);
        merged_targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(cat_key, merged_targets);
    }

    merged
}
