use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub target: String,
    pub target_ip: IpAddr,
    pub scan_type: ScanType,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub open_ports: Vec<PortInfo>,
    pub statistics: ScanStatistics,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub status: PortStatus,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
    pub response_time: Option<Duration>,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub confidence: u8, // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_ports: u16,
    pub open_ports: u16,
    pub closed_ports: u16,
    pub filtered_ports: u16,
    pub scan_duration: Duration,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub scanner_version: String,
    pub arguments: Vec<String>,
    pub hostname: Option<String>,
    pub os_detection: Option<OsInfo>,
    pub traceroute: Option<Vec<Hop>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: Option<String>,
    pub device_type: Option<String>,
    pub accuracy: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub ip: IpAddr,
    pub rtt: Duration,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Quick,      // Top 100 ports
    Standard,   // Top 1000 ports
    Full,       // All 65535 ports
    CustomRange(u16, u16),
    Targeted(Vec<u16>),
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub current_port: u16,
    pub total_ports: u16,
    pub percentage: f64,
    pub open_ports_found: u16,
    pub elapsed_time: Duration,
    pub estimated_remaining: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub max_concurrent_tasks: usize,
    pub retry_count: u8,
    pub rate_limit: Option<u32>, // Scans per second
    pub enable_service_detection: bool,
    pub enable_banner_grabbing: bool,
    pub enable_os_detection: bool,
    pub enable_traceroute: bool,
    pub stealth_mode: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            max_concurrent_tasks: 200,
            retry_count: 1,
            rate_limit: None,
            enable_service_detection: true,
            enable_banner_grabbing: true,
            enable_os_detection: false,
            enable_traceroute: false,
            stealth_mode: false,
        }
    }
}

impl ScanResult {
    pub fn new(target: String, target_ip: IpAddr, scan_type: ScanType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target,
            target_ip,
            scan_type,
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
            open_ports: Vec::new(),
            statistics: ScanStatistics::default(),
            metadata: ScanMetadata::default(),
        }
    }

    pub fn duration(&self) -> Duration {
        self.end_time.duration_since(self.start_time)
            .unwrap_or(Duration::from_secs(0))
    }

    pub fn add_open_port(&mut self, port_info: PortInfo) {
        self.open_ports.push(port_info);
        self.open_ports.sort_by_key(|p| p.port);
    }

    pub fn finalize(&mut self) {
        self.end_time = SystemTime::now();
        self.update_statistics();
    }

    fn update_statistics(&mut self) {
        let total = match &self.scan_type {
            ScanType::Quick => 100,
            ScanType::Standard => 1000,
            ScanType::Full => 65535,
            ScanType::CustomRange(start, end) => (end - start + 1),
            ScanType::Targeted(ports) => ports.len() as u16,
        };

        let open = self.open_ports.len() as u16;
        let closed = total - open; // Simplified

        self.statistics = ScanStatistics {
            total_ports: total,
            open_ports: open,
            closed_ports: closed,
            filtered_ports: 0,
            scan_duration: self.duration(),
            packets_sent: total as u64,
            packets_received: open as u64,
            success_rate: if total > 0 { (open as f64 / total as f64) * 100.0 } else { 0.0 },
        };
    }
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            arguments: std::env::args().collect(),
            hostname: None,
            os_detection: None,
            traceroute: None,
        }
    }
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self {
            total_ports: 0,
            open_ports: 0,
            closed_ports: 0,
            filtered_ports: 0,
            scan_duration: Duration::from_secs(0),
            packets_sent: 0,
            packets_received: 0,
            success_rate: 0.0,
        }
    }
}

// Common port lists
pub struct CommonPorts;

impl CommonPorts {
    pub fn top_100() -> Vec<u16> {
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443,
            // Fill with more common ports...
        ]
    }

    pub fn top_1000() -> Vec<u16> {
        // This would be a comprehensive list of top 1000 ports
        let mut ports = Self::top_100();
        // Add more ports...
        ports
    }

    pub fn all_ports() -> Vec<u16> {
        (1..=65535).collect()
    }
}
