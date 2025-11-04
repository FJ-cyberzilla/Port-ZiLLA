use super::Settings;
use crate::error::{Error, Result};

pub fn validate_settings(settings: &Settings) -> Result<()> {
    validate_scanner_settings(&settings.scanner)?;
    validate_database_settings(&settings.database)?;
    validate_security_settings(&settings.security)?;
    validate_export_settings(&settings.export)?;
    
    Ok(())
}

fn validate_scanner_settings(settings: &super::ScannerSettings) -> Result<()> {
    if settings.default_timeout_ms == 0 {
        return Err(Error::Validation("Scanner timeout must be greater than 0".to_string()));
    }
    
    if settings.max_threads == 0 {
        return Err(Error::Validation("Max threads must be greater than 0".to_string()));
    }
    
    if settings.chunk_size == 0 {
        return Err(Error::Validation("Chunk size must be greater than 0".to_string()));
    }
    
    if let Some(rate_limit) = settings.rate_limit {
        if rate_limit == 0 {
            return Err(Error::Validation("Rate limit must be greater than 0".to_string()));
        }
    }
    
    Ok(())
}

fn validate_database_settings(settings: &super::DatabaseSettings) -> Result<()> {
    if settings.connection_string.is_empty() {
        return Err(Error::Validation("Database connection string cannot be empty".to_string()));
    }
    
    if settings.max_connections == 0 {
        return Err(Error::Validation("Max connections must be greater than 0".to_string()));
    }
    
    if settings.backup_interval_hours == 0 {
        return Err(Error::Validation("Backup interval must be greater than 0".to_string()));
    }
    
    Ok(())
}

fn validate_security_settings(settings: &super::SecuritySettings) -> Result<()> {
    if settings.max_ports_per_scan == 0 {
        return Err(Error::Validation("Max ports per scan must be greater than 0".to_string()));
    }
    
    if settings.max_scans_per_hour == 0 {
        return Err(Error::Validation("Max scans per hour must be greater than 0".to_string()));
    }
    
    Ok(())
}

fn validate_export_settings(settings: &super::ExportSettings) -> Result<()> {
    if settings.output_directory.is_empty() {
        return Err(Error::Validation("Export output directory cannot be empty".to_string()));
    }
    
    Ok(())
}
