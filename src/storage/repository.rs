use super::{database::Database, models::*};
use crate::error::{Error, Result};
use crate::scanner::{ScanResult, PortInfo, ScanType};
use crate::vulnerability::{VulnerabilityReport, Vulnerability};
use sqlx::{query, query_as, QueryBuilder, Sqlite};
use std::collections::HashMap;
use tracing::{info, debug, instrument};

#[derive(Clone)]
pub struct ScanRepository {
    db: Database,
}

impl ScanRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    #[instrument(skip(self))]
    pub async fn save_scan(&self, scan_result: &ScanResult) -> Result<String> {
        let mut transaction = self.db.begin_transaction().await?;

        // Insert main scan record
        let scan_id = scan_result.id.clone();
        
        query(
            r#"
            INSERT INTO scans (
                id, target, target_ip, scan_type, start_time, end_time, 
                total_ports, open_ports, scan_duration_ms, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&scan_id)
        .bind(&scan_result.target)
        .bind(scan_result.target_ip.to_string())
        .bind(scan_type_to_string(&scan_result.scan_type))
        .bind(scan_result.start_time)
        .bind(scan_result.end_time)
        .bind(scan_result.statistics.total_ports as i32)
        .bind(scan_result.open_ports.len() as i32)
        .bind(scan_result.duration().as_millis() as i64)
        .bind("completed")
        .execute(&mut *transaction)
        .await?;

        // Insert port information
        for port_info in &scan_result.open_ports {
            self.insert_port_info(&mut transaction, &scan_id, port_info).await?;
        }

        // Insert scan statistics
        self.insert_scan_statistics(&mut transaction, &scan_id, &scan_result.statistics).await?;

        // Insert scan metadata
        self.insert_scan_metadata(&mut transaction, &scan_id, &scan_result.metadata).await?;

        transaction.commit().await?;
        
        info!("Scan saved successfully: {}", scan_id);
        Ok(scan_id)
    }

    async fn insert_port_info(
        &self,
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        scan_id: &str,
        port_info: &PortInfo,
    ) -> Result<()> {
        query(
            r#"
            INSERT INTO scan_ports (
                scan_id, port, status, service_name, service_version, 
                service_product, banner, response_time_ms, protocol
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(scan_id)
        .bind(port_info.port as i32)
        .bind(port_status_to_string(&port_info.status))
        .bind(port_info.service.as_ref().map(|s| &s.name))
        .bind(port_info.service.as_ref().and_then(|s| s.version.as_deref()))
        .bind(port_info.service.as_ref().and_then(|s| s.product.as_deref()))
        .bind(port_info.banner.as_deref())
        .bind(port_info.response_time.map(|d| d.as_millis() as i64))
        .bind(protocol_to_string(&port_info.protocol))
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    async fn insert_scan_statistics(
        &self,
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        scan_id: &str,
        stats: &crate::scanner::ScanStatistics,
    ) -> Result<()> {
        query(
            r#"
            INSERT INTO scan_statistics (
                scan_id, packets_sent, packets_received, success_rate, average_response_time_ms
            ) VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(scan_id)
        .bind(stats.packets_sent as i64)
        .bind(stats.packets_received as i64)
        .bind(stats.success_rate)
        .bind(stats.scan_duration.as_millis() as f64 / stats.total_ports.max(1) as f64)
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    async fn insert_scan_metadata(
        &self,
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        scan_id: &str,
        metadata: &crate::scanner::ScanMetadata,
    ) -> Result<()> {
        let arguments_json = serde_json::to_string(&metadata.arguments)?;
        let traceroute_json = metadata.traceroute.as_ref()
            .map(|t| serde_json::to_string(t))
            .transpose()?;

        query(
            r#"
            INSERT INTO scan_metadata (
                scan_id, scanner_version, arguments_json, hostname,
                os_name, os_version, os_accuracy, traceroute_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(scan_id)
        .bind(&metadata.scanner_version)
        .bind(&arguments_json)
        .bind(metadata.hostname.as_deref())
        .bind(metadata.os_detection.as_ref().map(|os| &os.name))
        .bind(metadata.os_detection.as_ref().and_then(|os| os.version.as_deref()))
        .bind(metadata.os_detection.as_ref().map(|os| os.accuracy as i32))
        .bind(traceroute_json.as_deref())
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_scan(&self, scan_id: &str) -> Result<Option<ScanRecord>> {
        let scan = query_as::<_, ScanRecord>(
            "SELECT * FROM scans WHERE id = ?"
        )
        .bind(scan_id)
        .fetch_optional(self.db.get_pool())
        .await?;

        Ok(scan)
    }

    #[instrument(skip(self))]
    pub async fn get_scan_history(&self, limit: Option<usize>) -> Result<Vec<ScanRecord>> {
        let limit = limit.unwrap_or(50) as i64;
        
        let scans = query_as::<_, ScanRecord>(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(self.db.get_pool())
        .await?;

        Ok(scans)
    }

    #[instrument(skip(self))]
    pub async fn search_scans(&self, query: ScanQuery) -> Result<PaginatedResults<ScanRecord>> {
        let mut sql = "SELECT * FROM scans WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(target) = &query.target {
            sql.push_str(" AND target LIKE ?");
            params.push(format!("%{}%", target));
        }

        if let Some(date_from) = &query.date_from {
            sql.push_str(" AND created_at >= ?");
            params.push(date_from.to_rfc3339());
        }

        if let Some(date_to) = &query.date_to {
            sql.push_str(" AND created_at <= ?");
            params.push(date_to.to_rfc3339());
        }

        if let Some(status) = &query.status {
            sql.push_str(" AND status = ?");
            params.push(status.clone());
        }

        sql.push_str(" ORDER BY created_at DESC");

        // Count total
        let count_sql = format!("SELECT COUNT(*) FROM ({})", sql.replace("*", "1"));
        let mut count_query = QueryBuilder::new(&count_sql);
        
        for param in &params {
            count_query.push_bind(param);
        }

        let total: (i64,) = count_query.build_query_as()
            .fetch_one(self.db.get_pool())
            .await?;

        // Apply pagination
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params.push(limit.to_string());
        }

        if let Some(offset) = query.offset {
            sql.push_str(" OFFSET ?");
            params.push(offset.to_string());
        }

        // Execute query
        let mut data_query = QueryBuilder::new(&sql);
        
        for param in &params {
            data_query.push_bind(param);
        }

        let data = data_query.build_query_as()
            .fetch_all(self.db.get_pool())
            .await?;

        let page_size = query.limit.unwrap_or(50);
        let page = query.offset.map(|o| o / page_size).unwrap_or(0);
        let total_pages = (total.0 as f64 / page_size as f64).ceil() as i64;

        Ok(PaginatedResults {
            data,
            total: total.0,
            page,
            page_size,
            total_pages,
        })
    }

    #[instrument(skip(self))]
    pub async fn get_scan_ports(&self, scan_id: &str) -> Result<Vec<ScanPortRecord>> {
        let ports = query_as::<_, ScanPortRecord>(
            "SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY port"
        )
        .bind(scan_id)
        .fetch_all(self.db.get_pool())
        .await?;

        Ok(ports)
    }

    #[instrument(skip(self))]
    pub async fn save_vulnerability_report(&self, report: &VulnerabilityReport) -> Result<String> {
        let mut transaction = self.db.begin_transaction().await?;

        for vulnerability in &report.vulnerabilities {
            self.insert_vulnerability(&mut transaction, &report.scan_id, vulnerability).await?;
        }

        transaction.commit().await?;
        
        info!("Vulnerability report saved for scan: {}", report.scan_id);
        Ok(report.id.clone())
    }

    async fn insert_vulnerability(
        &self,
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        scan_id: &str,
        vulnerability: &Vulnerability,
    ) -> Result<()> {
        let references_json = serde_json::to_string(&vulnerability.references)?;
        let tags_json = serde_json::to_string(&vulnerability.tags)?;

        query(
            r#"
            INSERT INTO vulnerabilities (
                id, scan_id, cve_id, title, description, level, cvss_score, cvss_vector,
                port, service, protocol, evidence, references_json, discovered_at,
                mitigation, exploit_available, impact, certainty, tags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&vulnerability.id)
        .bind(scan_id)
        .bind(vulnerability.cve_id.as_deref())
        .bind(&vulnerability.title)
        .bind(&vulnerability.description)
        .bind(vulnerability_level_to_string(&vulnerability.level))
        .bind(vulnerability.cvss_score)
        .bind(vulnerability.cvss_vector.as_deref())
        .bind(vulnerability.port as i32)
        .bind(&vulnerability.service)
        .bind(&vulnerability.protocol)
        .bind(&vulnerability.evidence)
        .bind(&references_json)
        .bind(vulnerability.discovered_at)
        .bind(&vulnerability.mitigation)
        .bind(vulnerability.exploit_available)
        .bind(&vulnerability.impact)
        .bind(vulnerability.certainty as i32)
        .bind(&tags_json)
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_vulnerabilities(&self, query: VulnerabilityQuery) -> Result<Vec<VulnerabilityRecord>> {
        let mut sql = "SELECT * FROM vulnerabilities WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(scan_id) = &query.scan_id {
            sql.push_str(" AND scan_id = ?");
            params.push(scan_id.clone());
        }

        if let Some(level) = &query.level {
            sql.push_str(" AND level = ?");
            params.push(level.clone());
        }

        if let Some(port) = query.port {
            sql.push_str(" AND port = ?");
            params.push(port.to_string());
        }

        if let Some(service) = &query.service {
            sql.push_str(" AND service = ?");
            params.push(service.clone());
        }

        if let Some(date_from) = &query.date_from {
            sql.push_str(" AND discovered_at >= ?");
            params.push(date_from.to_rfc3339());
        }

        if let Some(date_to) = &query.date_to {
            sql.push_str(" AND discovered_at <= ?");
            params.push(date_to.to_rfc3339());
        }

        sql.push_str(" ORDER BY discovered_at DESC");

        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params.push(limit.to_string());
        }

        let mut db_query = QueryBuilder::new(&sql);
        
        for param in &params {
            db_query.push_bind(param);
        }

        let vulnerabilities = db_query.build_query_as()
            .fetch_all(self.db.get_pool())
            .await?;

        Ok(vulnerabilities)
    }

    #[instrument(skip(self))]
    pub async fn get_scan_stats(&self) -> Result<ScanStats> {
        let stats = query_as::<_, (i64, i64, i64, f64, i64, f64)>(
            r#"
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_scans,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_scans,
                AVG(scan_duration_ms) as average_duration_ms,
                SUM(total_ports) as total_ports_scanned,
                AVG(open_ports) as average_open_ports
            FROM scans
            "#
        )
        .fetch_one(self.db.get_pool())
        .await?;

        Ok(ScanStats {
            total_scans: stats.0,
            successful_scans: stats.1,
            failed_scans: stats.2,
            average_duration_ms: stats.3,
            total_ports_scanned: stats.4,
            average_open_ports: stats.5,
        })
    }

    #[instrument(skip(self))]
    pub async fn get_vulnerability_stats(&self) -> Result<VulnerabilityStats> {
        let stats = query_as::<_, (i64, i64, i64, i64, i64, i64, f64)>(
            r#"
            SELECT 
                COUNT(*) as total_vulnerabilities,
                SUM(CASE WHEN level = 'critical' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN level = 'high' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN level = 'medium' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN level = 'low' THEN 1 ELSE 0 END) as low_count,
                SUM(CASE WHEN level = 'info' THEN 1 ELSE 0 END) as info_count,
                AVG(cvss_score) as average_cvss
            FROM vulnerabilities
            "#
        )
        .fetch_one(self.db.get_pool())
        .await?;

        Ok(VulnerabilityStats {
            total_vulnerabilities: stats.0,
            critical_count: stats.1,
            high_count: stats.2,
            medium_count: stats.3,
            low_count: stats.4,
            info_count: stats.5,
            average_cvss: stats.6.unwrap_or(0.0),
        })
    }

    #[instrument(skip(self))]
    pub async fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        let result = query("DELETE FROM scans WHERE id = ?")
            .bind(scan_id)
            .execute(self.db.get_pool())
            .await?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self))]
    pub async fn cleanup_old_scans(&self, older_than_days: i64) -> Result<u64> {
        let result = query(
            "DELETE FROM scans WHERE created_at < datetime('now', ?)"
        )
        .bind(format!("-{} days", older_than_days))
        .execute(self.db.get_pool())
        .await?;

        info!("Cleaned up {} old scans", result.rows_affected());
        Ok(result.rows_affected())
    }
}

// Conversion helper functions
fn scan_type_to_string(scan_type: &ScanType) -> String {
    match scan_type {
        ScanType::Quick => "quick".to_string(),
        ScanType::Standard => "standard".to_string(),
        ScanType::Full => "full".to_string(),
        ScanType::CustomRange(start, end) => format!("custom_{}_{}", start, end),
        ScanType::Targeted(_) => "targeted".to_string(),
    }
}

fn port_status_to_string(status: &crate::scanner::PortStatus) -> String {
    match status {
        crate::scanner::PortStatus::Open => "open",
        crate::scanner::PortStatus::Closed => "closed",
        crate::scanner::PortStatus::Filtered => "filtered",
        crate::scanner::PortStatus::OpenFiltered => "open_filtered",
        crate::scanner::PortStatus::Unknown => "unknown",
    }.to_string()
}

fn protocol_to_string(protocol: &crate::scanner::Protocol) -> String {
    match protocol {
        crate::scanner::Protocol::Tcp => "tcp",
        crate::scanner::Protocol::Udp => "udp",
        crate::scanner::Protocol::Sctp => "sctp",
    }.to_string()
}

fn vulnerability_level_to_string(level: &crate::vulnerability::VulnerabilityLevel) -> String {
    match level {
        crate::vulnerability::VulnerabilityLevel::Info => "info",
        crate::vulnerability::VulnerabilityLevel::Low => "low",
        crate::vulnerability::VulnerabilityLevel::Medium => "medium",
        crate::vulnerability::VulnerabilityLevel::High => "high",
        crate::vulnerability::VulnerabilityLevel::Critical => "critical",
    }.to_string()
      }
