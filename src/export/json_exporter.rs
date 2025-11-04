use super::Exporter;
use crate::error::Result;
use crate::scanner::ScanResult;
use crate::vulnerability::VulnerabilityReport;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use async_trait::async_trait;

pub struct JsonExporter;

impl JsonExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Exporter for JsonExporter {
    async fn export_scan(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<PathBuf> {
        let json_data = self.serialize_scan(scan)?;
        
        let mut file = File::create(output_path)?;
        serde_json::to_writer_pretty(&mut file, &json_data)?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    async fn export_vulnerability_report(&self, report: &VulnerabilityReport, output_path: &PathBuf) -> Result<PathBuf> {
        let json_data = self.serialize_vulnerability_report(report)?;
        
        let mut file = File::create(output_path)?;
        serde_json::to_writer_pretty(&mut file, &json_data)?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    fn get_file_extension(&self) -> &'static str {
        "json"
    }
}

impl JsonExporter {
    fn serialize_scan(&self, scan: &ScanResult) -> Result<Value> {
        let open_ports: Vec<Value> = scan.open_ports.iter().map(|port| {
            json!({
                "port": port.port,
                "status": format!("{:?}", port.status),
                "protocol": format!("{:?}", port.protocol),
                "service": port.service.as_ref().map(|s| {
                    json!({
                        "name": s.name,
                        "version": s.version,
                        "product": s.product,
                        "confidence": s.confidence
                    })
                }),
                "banner": port.banner,
                "response_time_ms": port.response_time.map(|d| d.as_millis() as u64)
            })
        }).collect();

        let json_data = json!({
            "metadata": {
                "scanner": "Port-ZiLLA Enterprise",
                "version": env!("CARGO_PKG_VERSION"),
                "scan_id": scan.id,
                "target": scan.target,
                "target_ip": scan.target_ip.to_string(),
                "scan_type": format!("{:?}", scan.scan_type),
                "start_time": scan.start_time.to_rfc3339(),
                "end_time": scan.end_time.to_rfc3339(),
                "duration_seconds": scan.duration().as_secs_f64()
            },
            "statistics": {
                "total_ports_scanned": scan.statistics.total_ports,
                "open_ports_found": scan.statistics.open_ports,
                "closed_ports": scan.statistics.closed_ports,
                "filtered_ports": scan.statistics.filtered_ports,
                "scan_duration_ms": scan.statistics.scan_duration.as_millis(),
                "packets_sent": scan.statistics.packets_sent,
                "packets_received": scan.statistics.packets_received,
                "success_rate": scan.statistics.success_rate
            },
            "results": {
                "open_ports": open_ports
            },
            "scan_metadata": {
                "scanner_version": scan.metadata.scanner_version,
                "hostname": scan.metadata.hostname,
                "os_detection": scan.metadata.os_detection.as_ref().map(|os| {
                    json!({
                        "name": os.name,
                        "version": os.version,
                        "device_type": os.device_type,
                        "accuracy": os.accuracy
                    })
                })
            }
        });

        Ok(json_data)
    }

    fn serialize_vulnerability_report(&self, report: &VulnerabilityReport) -> Result<Value> {
        let vulnerabilities: Vec<Value> = report.vulnerabilities.iter().map(|vuln| {
            json!({
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "description": vuln.description,
                "level": format!("{:?}", vuln.level),
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "port": vuln.port,
                "service": vuln.service,
                "protocol": vuln.protocol,
                "evidence": vuln.evidence,
                "references": vuln.references,
                "discovered_at": vuln.discovered_at.to_rfc3339(),
                "mitigation": vuln.mitigation,
                "exploit_available": vuln.exploit_available,
                "impact": vuln.impact,
                "certainty": vuln.certainty,
                "tags": vuln.tags
            })
        }).collect();

        let recommendations: Vec<Value> = report.recommendations.iter().map(|rec| {
            json!({
                "id": rec.id,
                "title": rec.title,
                "description": rec.description,
                "priority": format!("{:?}", rec.priority),
                "steps": rec.steps,
                "estimated_effort": rec.estimated_effort,
                "references": rec.references
            })
        }).collect();

        let json_data = json!({
            "metadata": {
                "report_id": report.id,
                "scan_id": report.scan_id,
                "target": report.target,
                "target_ip": report.target_ip.to_string(),
                "generated_at": report.generated_at.to_rfc3339(),
                "scanner": "Port-ZiLLA Enterprise",
                "version": env!("CARGO_PKG_VERSION")
            },
            "summary": {
                "total_vulnerabilities": report.summary.total_vulnerabilities,
                "critical_count": report.summary.critical_count,
                "high_count": report.summary.high_count,
                "medium_count": report.summary.medium_count,
                "low_count": report.summary.low_count,
                "info_count": report.summary.info_count,
                "risk_score": report.summary.risk_score,
                "average_cvss": report.summary.average_cvss
            },
            "risk_assessment": {
                "overall_risk": format!("{:?}", report.risk_assessment.overall_risk),
                "business_impact": report.risk_assessment.business_impact,
                "technical_impact": report.risk_assessment.technical_impact,
                "remediation_effort": format!("{:?}", report.risk_assessment.remediation_effort),
                "urgency": format!("{:?}", report.risk_assessment.urgency)
            },
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations
        });

        Ok(json_data)
    }
}

impl Default for JsonExporter {
    fn default() -> Self {
        Self::new()
    }
          }
