use super::Exporter;
use crate::error::Result;
use crate::scanner::ScanResult;
use crate::vulnerability::VulnerabilityReport;
use quick_xml::events::{BytesDecl, Event};
use quick_xml::Writer;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use async_trait::async_trait;

pub struct XmlExporter;

impl XmlExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Exporter for XmlExporter {
    async fn export_scan(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<PathBuf> {
        let xml_content = self.generate_scan_xml(scan)?;
        
        let mut file = File::create(output_path)?;
        file.write_all(xml_content.as_bytes())?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    async fn export_vulnerability_report(&self, report: &VulnerabilityReport, output_path: &PathBuf) -> Result<PathBuf> {
        let xml_content = self.generate_vulnerability_xml(report)?;
        
        let mut file = File::create(output_path)?;
        file.write_all(xml_content.as_bytes())?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    fn get_file_extension(&self) -> &'static str {
        "xml"
    }
}

impl XmlExporter {
    fn generate_scan_xml(&self, scan: &ScanResult) -> Result<String> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("portzilla_scan_report")))?;
        
        // Metadata
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("metadata")))?;
        self.write_xml_element(&mut writer, "scanner", "Port-ZiLLA Enterprise")?;
        self.write_xml_element(&mut writer, "version", env!("CARGO_PKG_VERSION"))?;
        self.write_xml_element(&mut writer, "scan_id", &scan.id)?;
        self.write_xml_element(&mut writer, "target", &scan.target)?;
        self.write_xml_element(&mut writer, "target_ip", &scan.target_ip.to_string())?;
        self.write_xml_element(&mut writer, "scan_type", &format!("{:?}", scan.scan_type))?;
        self.write_xml_element(&mut writer, "start_time", &scan.start_time.to_rfc3339())?;
        self.write_xml_element(&mut writer, "end_time", &scan.end_time.to_rfc3339())?;
        self.write_xml_element(&mut writer, "duration_seconds", &scan.duration().as_secs().to_string())?;
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("metadata")))?;
        
        // Statistics
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("statistics")))?;
        self.write_xml_element(&mut writer, "total_ports_scanned", &scan.statistics.total_ports.to_string())?;
        self.write_xml_element(&mut writer, "open_ports_found", &scan.statistics.open_ports.to_string())?;
        self.write_xml_element(&mut writer, "closed_ports", &scan.statistics.closed_ports.to_string())?;
        self.write_xml_element(&mut writer, "success_rate", &scan.statistics.success_rate.to_string())?;
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("statistics")))?;
        
        // Open ports
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("open_ports")))?;
        for port in &scan.open_ports {
            writer.write_event(Event::Start(quick_xml::events::BytesStart::new("port")))?;
            self.write_xml_element(&mut writer, "number", &port.port.to_string())?;
            self.write_xml_element(&mut writer, "status", &format!("{:?}", port.status))?;
            self.write_xml_element(&mut writer, "protocol", &format!("{:?}", port.protocol))?;
            
            if let Some(service) = &port.service {
                writer.write_event(Event::Start(quick_xml::events::BytesStart::new("service")))?;
                self.write_xml_element(&mut writer, "name", &service.name)?;
                if let Some(version) = &service.version {
                    self.write_xml_element(&mut writer, "version", version)?;
                }
                if let Some(product) = &service.product {
                    self.write_xml_element(&mut writer, "product", product)?;
                }
                self.write_xml_element(&mut writer, "confidence", &service.confidence.to_string())?;
                writer.write_event(Event::End(quick_xml::events::BytesEnd::new("service")))?;
            }
            
            if let Some(banner) = &port.banner {
                self.write_xml_element(&mut writer, "banner", banner)?;
            }
            
            if let Some(response_time) = port.response_time {
                self.write_xml_element(&mut writer, "response_time_ms", &response_time.as_millis().to_string())?;
            }
            
            writer.write_event(Event::End(quick_xml::events::BytesEnd::new("port")))?;
        }
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("open_ports")))?;
        
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("portzilla_scan_report")))?;
        
        Ok(String::from_utf8(writer.into_inner())?)
    }

    fn generate_vulnerability_xml(&self, report: &VulnerabilityReport) -> Result<String> {
        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("portzilla_vulnerability_report")))?;
        
        // Metadata
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("metadata")))?;
        self.write_xml_element(&mut writer, "report_id", &report.id)?;
        self.write_xml_element(&mut writer, "scan_id", &report.scan_id)?;
        self.write_xml_element(&mut writer, "target", &report.target)?;
        self.write_xml_element(&mut writer, "target_ip", &report.target_ip.to_string())?;
        self.write_xml_element(&mut writer, "generated_at", &report.generated_at.to_rfc3339())?;
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("metadata")))?;
        
        // Summary
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("summary")))?;
        self.write_xml_element(&mut writer, "total_vulnerabilities", &report.summary.total_vulnerabilities.to_string())?;
        self.write_xml_element(&mut writer, "critical_count", &report.summary.critical_count.to_string())?;
        self.write_xml_element(&mut writer, "high_count", &report.summary.high_count.to_string())?;
        self.write_xml_element(&mut writer, "medium_count", &report.summary.medium_count.to_string())?;
        self.write_xml_element(&mut writer, "low_count", &report.summary.low_count.to_string())?;
        self.write_xml_element(&mut writer, "info_count", &report.summary.info_count.to_string())?;
        self.write_xml_element(&mut writer, "risk_score", &report.summary.risk_score.to_string())?;
        self.write_xml_element(&mut writer, "average_cvss", &report.summary.average_cvss.to_string())?;
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("summary")))?;
        
        // Vulnerabilities
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new("vulnerabilities")))?;
        for vuln in &report.vulnerabilities {
            writer.write_event(Event::Start(quick_xml::events::BytesStart::new("vulnerability")))?;
            self.write_xml_element(&mut writer, "id", &vuln.id)?;
            if let Some(cve_id) = &vuln.cve_id {
                self.write_xml_element(&mut writer, "cve_id", cve_id)?;
            }
            self.write_xml_element(&mut writer, "title", &vuln.title)?;
            self.write_xml_element(&mut writer, "description", &vuln.description)?;
            self.write_xml_element(&mut writer, "level", &format!("{:?}", vuln.level))?;
            if let Some(cvss_score) = vuln.cvss_score {
                self.write_xml_element(&mut writer, "cvss_score", &cvss_score.to_string())?;
            }
            self.write_xml_element(&mut writer, "port", &vuln.port.to_string())?;
            self.write_xml_element(&mut writer, "service", &vuln.service)?;
            self.write_xml_element(&mut writer, "evidence", &vuln.evidence)?;
            self.write_xml_element(&mut writer, "mitigation", &vuln.mitigation)?;
            self.write_xml_element(&mut writer, "certainty", &vuln.certainty.to_string())?;
            self.write_xml_element(&mut writer, "exploit_available", &vuln.exploit_available.to_string())?;
            writer.write_event(Event::End(quick_xml::events::BytesEnd::new("vulnerability")))?;
        }
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("vulnerabilities")))?;
        
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new("portzilla_vulnerability_report")))?;
        
        Ok(String::from_utf8(writer.into_inner())?)
    }

    fn write_xml_element<W: std::io::Write>(
        &self,
        writer: &mut Writer<W>,
        name: &str,
        value: &str,
    ) -> Result<()> {
        writer.write_event(Event::Start(quick_xml::events::BytesStart::new(name)))?;
        writer.write_event(Event::Text(quick_xml::events::BytesText::new(value)))?;
        writer.write_event(Event::End(quick_xml::events::BytesEnd::new(name)))?;
        Ok(())
    }
}

impl Default for XmlExporter {
    fn default() -> Self {
        Self::new()
    }
      }
