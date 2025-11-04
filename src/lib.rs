//! PortScanner Enterprise - Enterprise-grade port scanning and vulnerability assessment tool
//! 
//! # Features
//! - High-performance asynchronous port scanning
//! - Multiple scan types (TCP, SYN, UDP)
//! - Vulnerability assessment with CVE database
//! - Comprehensive reporting and export capabilities
//! - Web dashboard and REST API
//! - Persistent storage with SQL database
//! - Configuration management
//! - Security controls and rate limiting

pub mod cli;
pub mod scanner;
pub mod vulnerability;
pub mod network;
pub mod export;
pub mod storage;
pub mod config;
pub mod ui;
pub mod web;
pub mod error;
pub mod utils;

// Re-export commonly used types
pub use config::Settings;
pub use error::{Error, Result};

// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[macro_use]
extern crate tracing;

// Prelude for common imports
pub mod prelude {
    pub use crate::error::{Error, Result};
    pub use crate::config::Settings;
    pub use tracing::{debug, error, info, warn};
}
