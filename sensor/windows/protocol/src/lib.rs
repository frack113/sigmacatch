// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Wire protocol shared by the kernel sensor and the user-mode client.
//!
//! Both sides depend on this crate, so the record layout and the kind
//! discriminants cannot drift. The crate is `no_std` and dependency-free to
//! stay linkable into the WDK driver.

#![no_std]

mod protocol;

pub use protocol::{
    IOCTL_GET_VERSION, IOCTL_READ_EVENTS, RING_CAPACITY, SIGMACATCH_PROTOCOL_VERSION, SensorEvent,
    kind,
};
