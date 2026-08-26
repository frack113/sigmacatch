// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch-linux-ebpf` — thin wrapper over the shared Linux entry (adds the native eBPF probes).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sigmacatch_lnx::entry::run().await
}
