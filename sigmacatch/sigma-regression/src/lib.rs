// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ regression-data `info.yml` model and file lifecycle.
//!
//! Every piece of the upstream regression specification lives here: the YAML
//! schema, its canonical 4-space layout, the accepted `type` spellings and the
//! Windows long-path handling. Readers of regression data depend on this crate
//! only, so a future specification change is confined to one place.
//!
//! # Example
//!
//! ```rust,no_run
//! use sigma_regression::InfoYml;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let info = InfoYml::load(Path::new("info.yml"))?;
//! println!("{} declares {} test(s)", info.id, info.regression_tests_info.len());
//! # Ok(())
//! # }
//! ```

pub mod indent;
pub mod info;
pub mod logtype;
mod long_path;

pub use info::{InfoYml, RegressionTestInfo, RuleMetadata, TestConfig};
pub use logtype::LogType;
pub use long_path::long_path;

/// Failure while reading, writing or interpreting an `info.yml` document.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file could not be read or written.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// The document could not be parsed or serialized as YAML.
    #[error("yaml error: {0}")]
    Yaml(String),
    /// The parsed document does not satisfy the regression contract.
    #[error("{0}")]
    Invalid(String),
}

/// Result alias over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
