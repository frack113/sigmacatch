// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch-linux` — thin wrapper over the shared Linux entry (auditd + builtin syslog).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sigmacatch_lnx::entry::run().await
}
