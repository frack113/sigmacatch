// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! End-to-end: Sysmon-for-Linux syslog line → collector parse → detection
//! engine (Linux pipelines) → alert. Uses real SigmaHQ rule files.

use sigmacatch_detection::DetectionEngine;
use sigmacatch_lnx::sysmon;
use sigmacatch_rule::SigmahqRules;

const SUDO_CVE_LINE: &[u8] = br#"<134>Aug 23 10:30:16 sigmacatch-linux sysmon: <Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-08-23T08:30:16.754997Z"/><EventRecordID>75947</EventRecordID><Correlation/><Execution ProcessID="1120" ThreadID="1120"/><Channel>Linux-Sysmon/Operational</Channel><Computer>sigmacatch-linux</Computer><Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-08-23 08:30:16.750</Data><Data Name="ProcessGuid">{ae88b96f-a8aa-6a8a-ad9d-cfc3e2550000}</Data><Data Name="ProcessId">6201</Data><Data Name="Image">/usr/bin/sudo</Data><Data Name="FileVersion">-</Data><Data Name="Description">-</Data><Data Name="Product">-</Data><Data Name="Company">-</Data><Data Name="OriginalFileName">-</Data><Data Name="CommandLine">sudo -u#-1 id</Data><Data Name="CurrentDirectory">/root</Data><Data Name="User">root</Data><Data Name="LogonGuid">{ae88b96f-0000-0000-0000-000000000000}</Data><Data Name="LogonId">0</Data><Data Name="TerminalSessionId">4294967295</Data><Data Name="IntegrityLevel">no level</Data><Data Name="Hashes">SHA256=157ccb43fb9cc077f1afa3220ad9b57900a71b47d26ba395526b5087be8a7f71</Data><Data Name="ParentProcessGuid">{ae88b96f-a8aa-6a8a-c521-477bd6550000}</Data><Data Name="ParentProcessId">1123</Data><Data Name="ParentImage">/usr/bin/bash</Data><Data Name="ParentCommandLine">bash</Data><Data Name="ParentUser">root</Data></EventData></Event>"#;

const WGET_TMP_LINE: &[u8] = br#"<134>Aug 23 10:30:17 sigmacatch-linux sysmon: <Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><TimeCreated SystemTime="2026-08-23T08:30:17.100Z"/><EventRecordID>75951</EventRecordID><Channel>Linux-Sysmon/Operational</Channel><Computer>sigmacatch-linux</Computer></System><EventData><Data Name="UtcTime">2026-08-23 08:30:17.099</Data><Data Name="ProcessId">6210</Data><Data Name="Image">/usr/bin/wget</Data><Data Name="CommandLine">wget --quiet -O /tmp/art_marker.txt https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh</Data><Data Name="User">root</Data><Data Name="ParentImage">/usr/bin/bash</Data></EventData></Event>"#;

fn eval_line(line: &[u8], rule_files: &[&str]) -> usize {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    for rf in rule_files {
        let dest = rules_dir.join(rf.rsplit('/').next().unwrap());
        std::fs::copy(rf, dest).unwrap();
    }

    let rules = SigmahqRules::new_from_path(dir.path().join("sigma").as_path()).unwrap();
    assert!(!rules.is_empty(), "rules must load");

    let record = sysmon::parse_line(line).expect("line must parse as sysmon");
    let event = sysmon::record_to_event(line, &record).expect("event must build");
    assert_eq!(event.event_json["product"], "linux");
    assert_eq!(event.event_json["service"], "sysmon");
    assert_eq!(event.event_json["category"], "process_creation");

    let mut engine = DetectionEngine::new(&rules).unwrap();
    engine.put_events(vec![event]);
    engine.process_events();
    engine.get_alerts().len()
}

#[test]
fn cve_2019_14287_sudo_dash_u_hash_matches() {
    let n = eval_line(
        SUDO_CVE_LINE,
        &[
            "../sigma/rules-emerging-threats/2019/Exploits/CVE-2019-14287/proc_creation_lnx_exploit_cve_2019_14287.yml",
            "../sigma/rules-emerging-threats/2019/Exploits/CVE-2019-14287/lnx_sudo_exploit_cve_2019_14287.yml",
        ],
    );
    assert!(
        n > 0,
        "sudo -u#-1 must match CVE-2019-14287 rule(s), got {n} alerts"
    );
}

#[test]
fn wget_download_suspicious_directory_matches() {
    let n = eval_line(
        WGET_TMP_LINE,
        &[
            "../sigma/rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.yml",
        ],
    );
    assert!(
        n > 0,
        "wget -O /tmp/... must match wget suspicious dir rule(s), got {n} alerts"
    );
}
