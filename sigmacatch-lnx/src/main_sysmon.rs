// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch-linux-sysmon` — thin wrapper over the shared Linux entry (adds the legacy Sysmon-for-Linux tail).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sigmacatch_lnx::entry::run().await
}
