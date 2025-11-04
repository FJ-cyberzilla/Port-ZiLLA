use super::Exporter;
use crate::error::Result;
use crate::scanner::ScanResult;
use crate::vulnerability::VulnerabilityReport;
use csv::Writer;
use std::fs::File;
use std::path::PathBuf;
use async_trait::async_trait;

pub struct CsvExporter;

impl CsvExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Exporter for CsvExporter {
    async fn export_scan(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<PathBuf> {
        // Create ports CSV
        let ports_path = output_path.with_extension("ports.csv");
        self.export_ports_csv(scan, &ports_path).await?;
        
        // Create summary CSV
        let summary_path = output_path.with_extension("summary.csv");
        self.export_summary_csv(scan, &summary_path).await?;
        
        Ok(output_path.clone())
    }

    async fn export_vulnerability_report(&self, report: &VulnerabilityReport, output_path: &PathBuf) -> Result<PathBuf> {
        let mut writer = Writer::from_path(output_path)?;
        
        // Write header
        writer.write_record(&[
            "Vulnerability ID",
            "CVE ID",
            "Title",
            "Level",
            "CVSS Score",
            "Port",
            "Service",
            "Evidence",
            "Mitigation",
            "Certainty",
            "Exploit Available"
        ])?;
        
        // Write data
        for vuln in &report.vulnerabilities {
            writer.write_record(&[
                &vuln.id,
                vuln.cve_id.as_deref().unwrap_or("N/A"),
                &vuln.title,
                &format!("{:?}", vuln.level),
                &vuln.cvss_score.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string()),
                &vuln.port.to_string(),
                &vuln.service,
                &vuln.evidence,
                &vuln.mitigation,
                &vuln.certainty.to_string(),
                &vuln.exploit_available.to_string()
            ])?;
        }
        
        writer.flush()?;
        Ok(output_path.clone())
    }

    fn get_file_extension(&self) -> &'static str {
        "csv"
    }
}

impl CsvExporter {
    async fn export_ports_csv(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<()> {
        let mut writer = Writer::from_path(output_path)?;
        
        writer.write_record(&[
            "Port",
            "Status",
            "Protocol",
            "Service Name",
            "Service Version",
            "Service Product",
            "Banner",
            "Response Time (ms)"
        ])?;
        
        for port_info in &scan.open_ports {
            writer.write_record(&[
                &port_info.port.to_string(),
                &format!("{:?}", port_info.status),
                &format!("{:?}", port_info.protocol),
                port_info.service.as_ref().map(|s| s.name.as_str()).unwrap_or(""),
                port_info.service.as_ref().and_then(|s| s.version.as_deref()).unwrap_or(""),
                port_info.service.as_ref().and_then(|s| s.product.as_deref()).unwrap_or(""),
                port_info.banner.as_deref().unwrap_or(""),
                &port_info.response_time.map(|d| d.as_millis().to_string()).unwrap_or_else(|| "".to_string())
            ])?;
        }
        
        writer.flush()?;
        Ok(())
    }

    async fn export_summary_csv(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<()> {
        let mut writer = Writer::from_path(output_path)?;
        
        writer.write_record(&[
            "Scan ID",
            "Target",
            "Target IP",
            "Scan Type",
            "Start Time",
            "End Time",
            "Duration (ms)",
            "Total Ports",
            "Open Ports",
            "Closed Ports",
            "Success Rate"
        ])?;
        
        writer.write_record(&[
            &scan.id,
            &scan.target,
            &scan.target_ip.to_string(),
            &format!("{:?}", scan.scan_type),
            &scan.start_time.to_rfc3339(),
            &scan.end_time.to_rfc3339(),
            &scan.duration().as_millis().to_string(),
            &scan.statistics.total_ports.to_string(),
            &scan.statistics.open_ports.to_string(),
            &scan.statistics.closed_ports.to_string(),
            &scan.statistics.success_rate.to_string()
        ])?;
        
        writer.flush()?;
        Ok(())
    }
}

impl Default for CsvExporter {
    fn default() -> Self {
        Self::new()
    }
}
