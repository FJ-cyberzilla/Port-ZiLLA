use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use chrono::{DateTime, Utc};

// Scan database models
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub target: String,
    pub target_ip: String,
    pub scan_type: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub total_ports: i32,
    pub open_ports: i32,
    pub scan_duration_ms: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanPortRecord {
    pub id: i64,
    pub scan_id: String,
    pub port: i32,
    pub status: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
    pub banner: Option<String>,
    pub response_time_ms: Option<i64>,
    pub protocol: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct VulnerabilityRecord {
    pub id: String,
    pub scan_id: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub level: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub port: i32,
    pub service: String,
    pub protocol: String,
    pub evidence: String,
    pub references_json: Option<String>,
    pub discovered_at: DateTime<Utc>,
    pub mitigation: String,
    pub exploit_available: bool,
    pub impact: Option<String>,
    pub certainty: i32,
    pub tags_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanStatisticsRecord {
    pub id: i64,
    pub scan_id: String,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub success_rate: f64,
    pub average_response_time_ms: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ScanMetadataRecord {
    pub id: i64,
    pub scan_id: String,
    pub scanner_version: String,
    pub arguments_json: Option<String>,
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_accuracy: Option<i32>,
    pub traceroute_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

// Query parameters
#[derive(Debug, Clone)]
pub struct ScanQuery {
    pub target: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityQuery {
    pub scan_id: Option<String>,
    pub level: Option<String>,
    pub port: Option<i32>,
    pub service: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// Results with pagination
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedResults<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub total_pages: i64,
}

// Statistics and analytics
#[derive(Debug, Clone, Serialize)]
pub struct ScanStats {
    pub total_scans: i64,
    pub successful_scans: i64,
    pub failed_scans: i64,
    pub average_duration_ms: f64,
    pub total_ports_scanned: i64,
    pub average_open_ports: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityStats {
    pub total_vulnerabilities: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub average_cvss: f64,
}

// Conversion traits
pub trait FromDatabase {
    type Output;
    fn from_database(record: Self) -> Self::Output;
}

pub trait ToDatabase {
    type Output;
    fn to_database(self) -> Self::Output;
  }
