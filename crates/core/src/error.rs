//! Error types for the core crate.

use thiserror::Error;

/// Result alias used across the core crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced while handling keys and configuration.
#[derive(Debug, Error)]
pub enum Error {
    /// A base64-encoded key could not be decoded.
    #[error("invalid base64 in key: {0}")]
    KeyDecode(#[from] base64::DecodeError),

    /// A key did not decode to exactly 32 bytes.
    #[error("key must be 32 bytes, got {0}")]
    KeyLength(usize),

    /// The configuration file could not be read.
    #[error("could not read config file '{path}': {source}")]
    ConfigRead {
        /// Path that failed to read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The configuration file could not be parsed as TOML.
    #[error("invalid config TOML: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// A configuration value failed validation.
    #[error("invalid config: {0}")]
    ConfigInvalid(String),
}
