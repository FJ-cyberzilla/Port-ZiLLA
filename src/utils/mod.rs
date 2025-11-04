use crate::error::Result;
use tracing_subscriber::{fmt, EnvFilter};
use tracing::Level;

/// Initialize logging system
pub fn setup_logging(default_level: Level) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.to_string().to_lowercase()));
    
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
    
    Ok(())
}

/// Validate IP address or hostname
pub fn validate_target(target: &str) -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    
    if target.parse::<IpAddr>().is_ok() 
        || target.parse::<Ipv4Addr>().is_ok() 
        || target.parse::<Ipv6Addr>().is_ok() 
        || is_valid_hostname(target) {
        Ok(())
    } else {
        Err(crate::error::Error::Validation(format!("Invalid target: {}", target)))
    }
}

/// Check if string is a valid hostname
pub fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.len() > 253 {
        return false;
    }
    
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    
    true
}

/// Calculate estimated scan time
pub fn estimate_scan_time(port_count: u16, threads: usize, timeout_ms: u64) -> std::time::Duration {
    let batches = (port_count as f64 / threads as f64).ceil() as u64;
    std::time::Duration::from_millis(batches * timeout_ms)
}

/// Generate a unique scan ID
pub fn generate_scan_id() -> String {
    use chrono::Utc;
    use uuid::Uuid;
    
    format!("{}-{}", Utc::now().format("%Y%m%d-%H%M%S"), Uuid::new_v4().simple())
}

/// Format duration for display
pub fn format_duration(duration: &std::time::Duration) -> String {
    if duration.as_secs() > 60 {
        format!("{:.2}m", duration.as_secs_f64() / 60.0)
    } else if duration.as_secs() > 1 {
        format!("{:.2}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

/// Format file size for display
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let digit_groups = (bytes as f64).log10().div_euclid(1024.0_f64.log10()) as usize;
    let size = bytes as f64 / 1024.0_f64.powi(digit_groups as i32);
    
    format!("{:.2} {}", size, UNITS[digit_groups])
}
