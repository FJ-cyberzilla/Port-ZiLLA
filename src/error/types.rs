use thiserror::Error;
use std::net::AddrParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Security violation: {0}")]
    Security(String),
    
    #[error("Scan error: {0}")]
    Scan(String),
    
    #[error("Vulnerability database error: {0}")]
    VulnerabilityDb(String),
    
    #[error("Export error: {0}")]
    Export(String),
    
    #[error("Target resolution error: {0}")]
    TargetResolution(String),
    
    #[error("Authentication error: {0}")]
    Auth(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::TargetResolution(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
