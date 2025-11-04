use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub scanner: ScannerSettings,
    pub database: DatabaseSettings,
    pub export: ExportSettings,
    pub security: SecuritySettings,
    pub logging: LoggingSettings,
    pub ui: UiSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerSettings {
    pub default_timeout_ms: u64,
    pub max_threads: usize,
    pub chunk_size: usize,
    pub syn_scan_enabled: bool,
    pub udp_scan_enabled: bool,
    pub rate_limit: Option<u32>,
    pub stealth_mode: bool,
    pub enable_service_detection: bool,
    pub enable_banner_grabbing: bool,
    pub enable_os_detection: bool,
    pub enable_traceroute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub connection_string: String,
    pub max_connections: u32,
    pub enable_migrations: bool,
    pub backup_enabled: bool,
    pub backup_interval_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSettings {
    pub default_format: ExportFormat,
    pub auto_export: bool,
    pub output_directory: String,
    pub include_timestamps: bool,
    pub compress_exports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub allowed_targets: Vec<IpAddr>,
    pub max_ports_per_scan: u16,
    pub require_authentication: bool,
    pub rate_limiting_enabled: bool,
    pub max_scans_per_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSettings {
    pub level: LogLevel,
    pub format: LogFormat,
    pub enable_file_logging: bool,
    pub log_directory: String,
    pub max_log_size_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSettings {
    pub color_scheme: ColorScheme,
    pub show_animations: bool,
    pub progress_bars_enabled: bool,
    pub detailed_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Pdf,
    Html,
    Xml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Simple,
    Detailed,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorScheme {
    Dark,
    Light,
    Auto,
}

impl Settings {
    pub fn load(config_path: &PathBuf) -> Result<Self> {
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            let settings: Settings = toml::from_str(&content)?;
            Ok(settings)
        } else {
            let settings = Settings::default();
            settings.save(config_path)?;
            Ok(settings)
        }
    }

    pub fn save(&self, config_path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(config_path, content)?;
        Ok(())
    }

    pub fn is_target_allowed(&self, target: &str) -> bool {
        if self.security.allowed_targets.is_empty() {
            return true; // No restrictions
        }

        if let Ok(ip_addr) = target.parse::<IpAddr>() {
            self.security.allowed_targets.contains(&ip_addr)
        } else {
            // For hostnames, we might want to resolve and check
            // For now, allow all hostnames if IP restrictions are set
            true
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            scanner: ScannerSettings::default(),
            database: DatabaseSettings::default(),
            export: ExportSettings::default(),
            security: SecuritySettings::default(),
            logging: LoggingSettings::default(),
            ui: UiSettings::default(),
        }
    }
}

impl Default for ScannerSettings {
    fn default() -> Self {
        Self {
            default_timeout_ms: 1000,
            max_threads: 200,
            chunk_size: 100,
            syn_scan_enabled: false,
            udp_scan_enabled: false,
            rate_limit: None,
            stealth_mode: false,
            enable_service_detection: true,
            enable_banner_grabbing: true,
            enable_os_detection: false,
            enable_traceroute: false,
        }
    }
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            connection_string: "sqlite:portzilla.db".to_string(),
            max_connections: 20,
            enable_migrations: true,
            backup_enabled: true,
            backup_interval_hours: 24,
        }
    }
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            default_format: ExportFormat::Json,
            auto_export: false,
            output_directory: "exports".to_string(),
            include_timestamps: true,
            compress_exports: false,
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            allowed_targets: Vec::new(), // Empty means all targets allowed
            max_ports_per_scan: 65535,
            require_authentication: false,
            rate_limiting_enabled: true,
            max_scans_per_hour: 10,
        }
    }
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Detailed,
            enable_file_logging: true,
            log_directory: "logs".to_string(),
            max_log_size_mb: 100,
        }
    }
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            color_scheme: ColorScheme::Dark,
            show_animations: true,
            progress_bars_enabled: true,
            detailed_output: true,
        }
    }
         }
