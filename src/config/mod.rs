pub mod settings;
pub mod validation;

pub use settings::{Settings, ScannerSettings, DatabaseSettings, ExportSettings, SecuritySettings, LoggingSettings};
pub use validation::validate_settings;

use crate::error::{Error, Result};
use std::path::PathBuf;

pub struct ConfigManager {
    settings: Settings,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let config_path = Self::get_config_path()?;
        let settings = Settings::load(&config_path)?;
        
        Ok(Self {
            settings,
            config_path,
        })
    }

    pub fn with_config_path(config_path: PathBuf) -> Result<Self> {
        let settings = Settings::load(&config_path)?;
        
        Ok(Self {
            settings,
            config_path,
        })
    }

    pub fn get_settings(&self) -> &Settings {
        &self.settings
    }

    pub fn get_settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    pub fn save_settings(&self) -> Result<()> {
        self.settings.save(&self.config_path)
    }

    pub fn reload(&mut self) -> Result<()> {
        self.settings = Settings::load(&self.config_path)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        validate_settings(&self.settings)
    }

    fn get_config_path() -> Result<PathBuf> {
        let mut path = std::env::current_dir()?;
        path.push("config");
        path.push("default.toml");
        
        // Create config directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        Ok(path)
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback to default settings if config file doesn't exist
            let settings = Settings::default();
            let config_path = Self::get_config_path().unwrap_or_else(|_| PathBuf::from("config/default.toml"));
            
            Self {
                settings,
                config_path,
            }
        })
    }
}
