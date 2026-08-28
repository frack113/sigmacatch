// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! eBPF-based sysmon input: loads the probes embedded by `src/build.rs`,
//! checks privileges at startup, attaches the tracepoints and produces
//! Sysmon-schema events from the kernel ring buffer.

use std::fs;

use anyhow::{Context, bail};
use async_trait::async_trait;
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use sigmacatch_ebpf_common::{
    DnsEvent, EVENT_DNS, EVENT_EXEC, EVENT_EXIT, EVENT_FILE, EVENT_NET, FileCreateEvent, NetEvent,
};
use sigmacatch_types::{Event, EventProducer, ProducerError};
use tokio::sync::{mpsc, watch};
use tracing::info;

use crate::ebpf_event::EventBuilder;

const RING_POLL_MS: u64 = 100;

/// Object embedded by `src/build.rs`: real probes when the nightly toolchain
/// was available at build time, an empty placeholder otherwise (the loader
/// rejects it and collection falls back to the legacy syslog tail).
static PROBE_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sigmacatch_ebpf.o"));

const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_PERFMON: u64 = 1 << 38;
const CAP_BPF: u64 = 1 << 39;

/// True when the process may load eBPF programs: root, CAP_SYS_ADMIN
/// (legacy gating), or both CAP_BPF and CAP_PERFMON.
pub fn has_required_privileges() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => privileges_from_status(&status),
        Err(_) => false,
    }
}

/// Pure decision over a `/proc/self/status` payload.
fn privileges_from_status(status: &str) -> bool {
    if is_root(status) {
        return true;
    }
    match cap_eff(status) {
        Some(caps) => caps & CAP_SYS_ADMIN != 0 || caps & CAP_BPF != 0 && caps & CAP_PERFMON != 0,
        None => false,
    }
}

/// Effective UID == 0, read from the `Uid:` line of `/proc/self/status`.
fn is_root(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
        == Some(0)
}

/// Hex value of the `CapEff:` line of `/proc/self/status`.
fn cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|rest| u64::from_str_radix(rest.trim(), 16).ok())
}

/// (probe name, tracepoint category, tracepoint name)
const ATTACHMENTS: &[(&str, &str, &str)] = &[
    ("sys_enter_execve", "syscalls", "sys_enter_execve"),
    ("sched_process_exec", "sched", "sched_process_exec"),
    ("sched_process_exit", "sched", "sched_process_exit"),
    ("sys_enter_connect", "syscalls", "sys_enter_connect"),
    ("sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("sys_exit_openat", "syscalls", "sys_exit_openat"),
    ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
    ("sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"),
];

/// eBPF-backed sysmon collector (feature `ebpf`): loads the embedded probe
/// object, attaches the tracepoints and produces Sysmon-XML events.
pub struct EventCollector {
    _ebpf: Ebpf,
    builder: EventBuilder,
}

impl EventCollector {
    /// Validate privileges, load the probe object and attach all tracepoints
    /// up front so the caller can fall back to the legacy syslog tail when
    /// eBPF is unusable.
    pub fn new() -> anyhow::Result<Self> {
        if !has_required_privileges() {
            bail!("insufficient privileges to load eBPF probes");
        }
        let mut ebpf = aya::EbpfLoader::new()
            .load(PROBE_OBJECT)
            .context("loading embedded eBPF object failed (built without nightly toolchain?)")?;
        if ebpf.map("EVENTS").is_none() {
            bail!("probe object has no EVENTS ring buffer (probes not implemented yet)");
        }

        // Attachments stay live for the process lifetime; aya 0.13 tracks
        // them inside each program (ids only needed to detach explicitly).
        for (name, category, tp) in ATTACHMENTS {
            let program: &mut TracePoint = ebpf
                .program_mut(name)
                .with_context(|| format!("probe {name} missing from object"))?
                .try_into()
                .with_context(|| format!("probe {name} is not a tracepoint"))?;
            program
                .load()
                .with_context(|| format!("loading probe {name}"))?;
            program
                .attach(category, tp)
                .with_context(|| format!("attaching probe {name} to {category}:{tp}"))?;
        }

        Ok(Self {
            _ebpf: ebpf,
            builder: EventBuilder::new(),
        })
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        mut self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        info!(
            "sysmon(ebpf) collector starting ({} tracepoints)",
            ATTACHMENTS.len()
        );
        let Some(data) = self._ebpf.map_mut("EVENTS") else {
            return Err(ProducerError::Message(
                "EVENTS ring buffer disappeared after attach".to_string(),
            ));
        };
        let mut ring = RingBuf::try_from(data).map_err(|e| {
            ProducerError::Collector(anyhow::anyhow!("mapping EVENTS ring buffer: {e}").into())
        })?;

        while !*stop.borrow() {
            tokio::time::sleep(std::time::Duration::from_millis(RING_POLL_MS)).await;
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                let Some([t0, t1, t2, t3]) = bytes.first_chunk::<4>() else {
                    tracing::warn!(size = bytes.len(), "short ring buffer record");
                    continue;
                };
                match u32::from_le_bytes([*t0, *t1, *t2, *t3]) {
                    EVENT_EXEC => match ExecEvent::from_bytes(bytes) {
                        Some(ev) => {
                            let event = self.builder.exec_event(&ev);
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                        None => tracing::warn!(
                            size = bytes.len(),
                            "exec record with unexpected size — skipped"
                        ),
                    },
                    EVENT_EXIT => match ExitEvent::from_bytes(bytes) {
                        Some(ev) => {
                            if let Some(event) = self.builder.exit_event(ev.pid)
                                && tx.send(event).await.is_err()
                            {
                                return Ok(());
                            }
                        }
                        None => tracing::warn!(
                            size = bytes.len(),
                            "exit record with unexpected size — skipped"
                        ),
                    },
                    EVENT_FILE => match FileCreateEvent::from_bytes(bytes) {
                        Some(ev) => {
                            let event = self.builder.file_create_event(&ev);
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                        None => tracing::warn!(
                            size = bytes.len(),
                            "file record with unexpected size — skipped"
                        ),
                    },
                    EVENT_DNS => match DnsEvent::from_bytes(bytes) {
                        Some(ev) => {
                            if let Some(event) = self.builder.dns_event(&ev)
                                && tx.send(event).await.is_err()
                            {
                                return Ok(());
                            }
                        }
                        None => tracing::warn!(
                            size = bytes.len(),
                            "dns record with unexpected size — skipped"
                        ),
                    },
                    EVENT_NET => match NetEvent::from_bytes(bytes) {
                        Some(ev) => {
                            let event = self.builder.net_event(&ev);
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                        None => tracing::warn!(
                            size = bytes.len(),
                            "net record with unexpected size — skipped"
                        ),
                    },
                    other => tracing::warn!(tag = other, "unknown ring buffer record tag"),
                }
            }
        }
        Ok(())
    }
}

use sigmacatch_ebpf_common::{ExecEvent, ExitEvent};

#[cfg(test)]
mod tests {
    use super::*;

    fn status(uid: u32, caps: u64) -> String {
        format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t{caps:016x}\n")
    }

    #[test]
    fn root_is_privileged_regardless_of_caps() {
        assert!(privileges_from_status(&status(0, 0)));
    }

    #[test]
    fn unprivileged_user_without_caps_is_rejected() {
        assert!(!privileges_from_status(&status(1000, 0)));
    }

    #[test]
    fn sys_admin_alone_grants_legacy_access() {
        assert!(privileges_from_status(&status(1000, CAP_SYS_ADMIN)));
    }

    #[test]
    fn bpf_requires_perfmon() {
        assert!(!privileges_from_status(&status(1000, CAP_BPF)));
        assert!(privileges_from_status(&status(1000, CAP_BPF | CAP_PERFMON)));
    }

    #[test]
    fn missing_or_malformed_lines_are_rejected() {
        assert!(!privileges_from_status(""));
        assert!(!privileges_from_status(
            "CapEff:\tzz\nUid:\t1000\t1000\t1000\t1000\n"
        ));
        assert_eq!(cap_eff("no line"), None);
    }
}
