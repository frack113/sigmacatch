// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Winevt multi-channel collector (feature `winevt`).
//!
//! Provides [`channels::EventCollector`], the async producer that collects
//! one or more Windows Event Log channels. The full Windows orchestrator
//! (channel resolution plus one process source) lives in `sigmacatch`'s
//! `orchestrators::windows`, which drives this producer through the runner.

pub mod channels;
