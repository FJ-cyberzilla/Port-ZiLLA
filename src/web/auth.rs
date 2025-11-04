use crate::error::{Error, Result};
use std::collections::HashSet;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key: String,
    pub name: String,
    pub permissions: HashSet<Permission>,
    pub rate_limit: Option<u32>, // requests per minute
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    ScanRead,
    ScanWrite,
    ScanDelete,
    ExportRead,
    ExportWrite,
    Admin,
}

pub struct ApiAuthenticator {
    api_keys: RwLock<Vec<ApiKey>>,
}

impl ApiAuthenticator {
    pub fn new() -> Self {
        // In production, load from secure config/database
        let mut default_keys = Vec::new();
        
        // Default admin key for initial setup
        default_keys.push(ApiKey {
            key: "portzilla-default-key-2024".to_string(),
            name: "Default Admin".to_string(),
            permissions: HashSet::from([
                Permission::ScanRead,
                Permission::ScanWrite, 
                Permission::ScanDelete,
                Permission::ExportRead,
                Permission::ExportWrite,
                Permission::Admin,
            ]),
            rate_limit: Some(1000), // 1000 requests per minute
        });

        Self {
            api_keys: RwLock::new(default_keys),
        }
    }

    pub fn authenticate(&self, api_key: &str, required_permission: &Permission) -> Result<()> {
        let keys = self.api_keys.read()
            .map_err(|_| Error::Auth("Failed to read API keys".to_string()))?;

        let key = keys.iter()
            .find(|k| k.key == api_key)
            .ok_or_else(|| Error::Auth("Invalid API key".to_string()))?;

        if !key.permissions.contains(required_permission) {
            return Err(Error::Auth("Insufficient permissions".to_string()));
        }

        Ok(())
    }

    pub fn add_api_key(&self, new_key: ApiKey) -> Result<()> {
        let mut keys = self.api_keys.write()
            .map_err(|_| Error::Auth("Failed to write API keys".to_string()))?;

        // Check for duplicates
        if keys.iter().any(|k| k.key == new_key.key) {
            return Err(Error::Auth("API key already exists".to_string()));
        }

        keys.push(new_key);
        Ok(())
    }

    pub fn remove_api_key(&self, key_to_remove: &str) -> Result<()> {
        let mut keys = self.api_keys.write()
            .map_err(|_| Error::Auth("Failed to write API keys".to_string()))?;

        keys.retain(|k| k.key != key_to_remove);
        Ok(())
    }

    pub fn validate_key_format(key: &str) -> bool {
        // Basic validation: at least 20 characters, alphanumeric + hyphens
        key.len() >= 20 && 
        key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}

impl Default for ApiAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}
