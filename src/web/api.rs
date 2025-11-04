use crate::error::{Error, Result};
use crate::scanner::{ScanEngine, ScanResult, ScanType};
use crate::vulnerability::VulnerabilityDetector;
use crate::storage::ScanRepository;
use crate::export::ExportManager;
use crate::config::ConfigManager;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub scan_type: ScanTypeDto,
    pub timeout_ms: Option<u64>,
    pub max_threads: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub status: String,
    pub target: String,
    pub scan_type: String,
    pub started_at: String,
    pub estimated_duration: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultResponse {
    pub scan_id: String,
    pub status: String,
    pub target: String,
    pub open_ports: usize,
    pub total_ports: u16,
    pub duration_seconds: f64,
    pub results: Vec<PortResultDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResultDto {
    pub port: u16,
    pub status: String,
    pub service: Option<ServiceDto>,
    pub banner: Option<String>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDto {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub scan_id: String,
    pub format: String,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanTypeDto {
    Quick,
    Standard,
    Full,
    Custom { start_port: u16, end_port: u16 },
}

pub struct ApiServer {
    scan_engine: Arc<ScanEngine>,
    vulnerability_detector: Arc<VulnerabilityDetector>,
    scan_repository: Arc<ScanRepository>,
    export_manager: Arc<ExportManager>,
    config: Arc<ConfigManager>,
    active_scans: Arc<Mutex<Vec<String>>>, // Track active scan IDs
}

impl ApiServer {
    pub fn new(
        scan_engine: Arc<ScanEngine>,
        vulnerability_detector: Arc<VulnerabilityDetector>,
        scan_repository: Arc<ScanRepository>,
        export_manager: Arc<ExportManager>,
        config: Arc<ConfigManager>,
    ) -> Self {
        Self {
            scan_engine,
            vulnerability_detector,
            scan_repository,
            export_manager,
            config,
            active_scans: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn start_server(&self, bind_addr: SocketAddr) -> Result<()> {
        info!("Starting Port-ZiLLA API server on {}", bind_addr);
        
        // We'll use Actix Web or Warp for the actual HTTP server
        // For now, implement the handler logic
        self.start_http_server(bind_addr).await
    }

    async fn start_http_server(&self, _bind_addr: SocketAddr) -> Result<()> {
        // Implementation would use Actix Web, Warp, or similar
        // This is where we'd define routes and start the server
        info!("HTTP server would start here on {}", _bind_addr);
        
        // Placeholder - actual implementation would be framework-specific
        Ok(())
    }

    // API Handler Methods
    pub async fn handle_start_scan(&self, request: ScanRequest, api_key: &str) -> Result<ScanResponse> {
        debug!("API: Starting scan for target: {}", request.target);
        
        // Validate target
        self.validate_target(&request.target)?;
        
        // Check rate limits
        // self.rate_limiter.check_rate_limit(api_key).await?;
        
        // Convert DTO to domain type
        let scan_type = self.convert_scan_type(request.scan_type)?;
        
        // Start scan (async, non-blocking)
        let scan_engine = Arc::clone(&self.scan_engine);
        let target = request.target.clone();
        let scan_type_clone = scan_type.clone();
        
        tokio::spawn(async move {
            match scan_engine.scan(&target, scan_type_clone).await {
                Ok(ScanResult { id, .. }) => {
                    info!("Scan completed successfully: {}", id);
                    // Save to repository, etc.
                }
                Err(e) => {
                    error!("Scan failed: {}", e);
                }
            }
        });

        // Generate response
        Ok(ScanResponse {
            scan_id: "temp-id".to_string(), // Would be actual scan ID
            status: "started".to_string(),
            target: request.target,
            scan_type: format!("{:?}", scan_type),
            started_at: chrono::Utc::now().to_rfc3339(),
            estimated_duration: "Estimating...".to_string(),
        })
    }

    pub async fn handle_get_scan(&self, scan_id: &str, _api_key: &str) -> Result<ScanResultResponse> {
        debug!("API: Getting scan results for: {}", scan_id);
        
        // Get scan from repository
        let scan_record = self.scan_repository.get_scan(scan_id).await?
            .ok_or_else(|| Error::Validation("Scan not found".to_string()))?;

        // Get port details
        let ports = self.scan_repository.get_scan_ports(scan_id).await?;
        
        // Convert to DTO
        let port_results: Vec<PortResultDto> = ports.into_iter().map(|port| {
            PortResultDto {
                port: port.port as u16,
                status: port.status,
                service: port.service_name.map(|name| ServiceDto {
                    name,
                    version: port.service_version,
                    product: port.service_product,
                    confidence: 80, // Default confidence
                }),
                banner: port.banner,
                response_time_ms: port.response_time_ms.map(|ms| ms as u64),
            }
        }).collect();

        Ok(ScanResultResponse {
            scan_id: scan_record.id,
            status: scan_record.status,
            target: scan_record.target,
            open_ports: port_results.len(),
            total_ports: scan_record.total_ports as u16,
            duration_seconds: scan_record.scan_duration_ms as f64 / 1000.0,
            results: port_results,
        })
    }

    pub async fn handle_export_scan(&self, request: ExportRequest, _api_key: &str) -> Result<String> {
        debug!("API: Exporting scan: {}", request.scan_id);
        
        // Get scan from repository
        let scan_record = self.scan_repository.get_scan(&request.scan_id).await?
            .ok_or_else(|| Error::Validation("Scan not found".to_string()))?;

        // Convert to domain ScanResult (simplified)
        // In real implementation, we'd reconstruct the full ScanResult
        let output_path = self.export_manager.export_scan(
            &scan_record.into(), // Would need conversion
            &request.format,
            request.output_path.map(std::path::PathBuf::from)
        ).await?;

        Ok(output_path.to_string_lossy().to_string())
    }

    pub async fn handle_get_scans(&self, _limit: Option<usize>, _api_key: &str) -> Result<Vec<ScanResponse>> {
        debug!("API: Listing scans");
        
        let scans = self.scan_repository.get_scan_history(_limit).await?;
        
        let responses: Vec<ScanResponse> = scans.into_iter().map(|scan| {
            ScanResponse {
                scan_id: scan.id,
                status: scan.status,
                target: scan.target,
                scan_type: scan.scan_type,
                started_at: scan.start_time.to_rfc3339(),
                estimated_duration: "Completed".to_string(),
            }
        }).collect();

        Ok(responses)
    }

    // Utility methods
    fn validate_target(&self, target: &str) -> Result<()> {
        // Basic target validation
        if target.is_empty() {
            return Err(Error::Validation("Target cannot be empty".to_string()));
        }

        // Check if target is in allowed list
        if !self.config.get_settings().security.is_target_allowed(target) {
            return Err(Error::Security("Target not in allowed list".to_string()));
        }

        // Validate format (IP or hostname)
        if target.parse::<IpAddr>().is_err() {
            // Basic hostname validation
            if target.len() > 253 {
                return Err(Error::Validation("Hostname too long".to_string()));
            }
            
            let labels: Vec<&str> = target.split('.').collect();
            for label in labels {
                if label.is_empty() || label.len() > 63 {
                    return Err(Error::Validation("Invalid hostname format".to_string()));
                }
            }
        }

        Ok(())
    }

    fn convert_scan_type(&self, dto: ScanTypeDto) -> Result<ScanType> {
        match dto {
            ScanTypeDto::Quick => Ok(ScanType::Quick),
            ScanTypeDto::Standard => Ok(ScanType::Standard),
            ScanTypeDto::Full => Ok(ScanType::Full),
            ScanTypeDto::Custom { start_port, end_port } => {
                if start_port > end_port {
                    return Err(Error::Validation("Start port must be <= end port".to_string()));
                }
                Ok(ScanType::CustomRange(start_port, end_port))
            }
        }
    }
}

// API Health Check
impl ApiServer {
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let database_healthy = self.scan_repository.health_check().await.unwrap_or(false);
        let active_scans = self.active_scans.lock().await.len();

        Ok(HealthStatus {
            status: if database_healthy { "healthy" } else { "degraded" }.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database_healthy,
            active_scans,
            uptime_seconds: 0, // Would track actual uptime
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub database_healthy: bool,
    pub active_scans: usize,
    pub uptime_seconds: u64,
  }
