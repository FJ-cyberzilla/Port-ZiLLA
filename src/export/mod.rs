pub mod json_exporter;
pub mod csv_exporter;
pub mod pdf_exporter;
pub mod html_exporter;
pub mod xml_exporter;

pub use json_exporter::JsonExporter;
pub use csv_exporter::CsvExporter;
pub use pdf_exporter::PdfExporter;
pub use html_exporter::HtmlExporter;
pub use xml_exporter::XmlExporter;

use crate::error::{Error, Result};
use crate::scanner::ScanResult;
use crate::vulnerability::VulnerabilityReport;
use std::path::PathBuf;
use async_trait::async_trait;

#[async_trait]
pub trait Exporter: Send + Sync {
    async fn export_scan(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<PathBuf>;
    async fn export_vulnerability_report(&self, report: &VulnerabilityReport, output_path: &PathBuf) -> Result<PathBuf>;
    fn get_file_extension(&self) -> &'static str;
}

pub struct ExportManager {
    exporters: std::collections::HashMap<String, Box<dyn Exporter>>,
}

impl ExportManager {
    pub fn new() -> Self {
        let mut exporters = std::collections::HashMap::new();
        
        // Register all exporters
        exporters.insert("json".to_string(), Box::new(JsonExporter::new()));
        exporters.insert("csv".to_string(), Box::new(CsvExporter::new()));
        exporters.insert("pdf".to_string(), Box::new(PdfExporter::new()));
        exporters.insert("html".to_string(), Box::new(HtmlExporter::new()));
        exporters.insert("xml".to_string(), Box::new(XmlExporter::new()));
        
        Self { exporters }
    }

    pub async fn export_scan(
        &self, 
        scan: &ScanResult, 
        format: &str, 
        output_path: Option<PathBuf>
    ) -> Result<PathBuf> {
        let exporter = self.exporters.get(format)
            .ok_or_else(|| Error::Export(format!("Unsupported export format: {}", format)))?;

        let output_path = output_path.unwrap_or_else(|| {
            Self::generate_default_filename(scan, exporter.get_file_extension())
        });

        exporter.export_scan(scan, &output_path).await?;
        
        Ok(output_path)
    }

    pub async fn export_vulnerability_report(
        &self,
        report: &VulnerabilityReport,
        format: &str,
        output_path: Option<PathBuf>
    ) -> Result<PathBuf> {
        let exporter = self.exporters.get(format)
            .ok_or_else(|| Error::Export(format!("Unsupported export format: {}", format)))?;

        let output_path = output_path.unwrap_or_else(|| {
            Self::generate_vulnerability_filename(report, exporter.get_file_extension())
        });

        exporter.export_vulnerability_report(report, &output_path).await?;
        
        Ok(output_path)
    }

    pub fn get_supported_formats(&self) -> Vec<&str> {
        self.exporters.keys().map(|s| s.as_str()).collect()
    }

    fn generate_default_filename(scan: &ScanResult, extension: &str) -> PathBuf {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let target_clean = scan.target.replace(['.', ':'], "_");
        PathBuf::from(format!("portzilla_scan_{}_{}.{}", target_clean, timestamp, extension))
    }

    fn generate_vulnerability_filename(report: &VulnerabilityReport, extension: &str) -> PathBuf {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let target_clean = report.target.replace(['.', ':'], "_");
        PathBuf::from(format!("portzilla_vuln_{}_{}.{}", target_clean, timestamp, extension))
    }
}

impl Default for ExportManager {
    fn default() -> Self {
        Self::new()
    }
                                 }
