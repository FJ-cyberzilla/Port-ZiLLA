use super::Exporter;
use crate::error::Result;
use crate::scanner::ScanResult;
use crate::vulnerability::VulnerabilityReport;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use async_trait::async_trait;

pub struct HtmlExporter;

impl HtmlExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Exporter for HtmlExporter {
    async fn export_scan(&self, scan: &ScanResult, output_path: &PathBuf) -> Result<PathBuf> {
        let html_content = self.generate_scan_html(scan)?;
        
        let mut file = File::create(output_path)?;
        file.write_all(html_content.as_bytes())?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    async fn export_vulnerability_report(&self, report: &VulnerabilityReport, output_path: &PathBuf) -> Result<PathBuf> {
        let html_content = self.generate_vulnerability_html(report)?;
        
        let mut file = File::create(output_path)?;
        file.write_all(html_content.as_bytes())?;
        file.flush()?;
        
        Ok(output_path.clone())
    }

    fn get_file_extension(&self) -> &'static str {
        "html"
    }
}

impl HtmlExporter {
    fn generate_scan_html(&self, scan: &ScanResult) -> Result<String> {
        let open_ports_rows: String = scan.open_ports.iter().map(|port| {
            let service_info = port.service.as_ref().map(|s| {
                format!("{} {} {}", s.name, s.version.as_deref().unwrap_or(""), s.product.as_deref().unwrap_or(""))
            }).unwrap_or_else(|| "Unknown".to_string());
            
            format!(
                r#"<tr>
                    <td>{}</td>
                    <td><span class="status-open">OPEN</span></td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>"#,
                port.port,
                format!("{:?}", port.protocol),
                service_info,
                port.banner.as_deref().unwrap_or(""),
                port.response_time.map(|d| format!("{}ms", d.as_millis())).unwrap_or_else(|| "N/A".to_string())
            )
        }).collect();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port-ZiLLA Scan Report - {}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #ffd700, #ffed4e); color: #1a1a1a; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .card {{ background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffd700; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #3d3d3d; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #ffd700; }}
        .ports-table {{ width: 100%; border-collapse: collapse; }}
        .ports-table th, .ports-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
        .ports-table th {{ background: #3d3d3d; color: #ffd700; }}
        .status-open {{ color: #4CAF50; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 40px; opacity: 0.7; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦖 Port-ZiLLA Enterprise</h1>
            <div class="subtitle">Professional Port Scanning & Security Assessment</div>
        </div>
        
        <div class="card">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div>Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{}</div>
                    <div>Total Ports Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{:.2}s</div>
                    <div>Scan Duration</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{:.1}%</div>
                    <div>Success Rate</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>🎯 Scan Details</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Target:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;">{} ({})</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Scan Type:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;">{:?}</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Start Time:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;">{}</td></tr>
                <tr><td style="padding: 8px;"><strong>End Time:</strong></td><td style="padding: 8px;">{}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>🔍 Open Ports</h2>
            <table class="ports-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Status</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Banner</th>
                        <th>Response Time</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by Port-ZiLLA Enterprise v{} | {} | Contact: cyberzilla.systems@gmail.com
        </div>
    </div>
</body>
</html>"#,
            scan.target,
            scan.open_ports.len(),
            scan.statistics.total_ports,
            scan.duration().as_secs_f64(),
            scan.statistics.success_rate,
            scan.target,
            scan.target_ip,
            scan.scan_type,
            scan.start_time.to_rfc3339(),
            scan.end_time.to_rfc3339(),
            open_ports_rows,
            env!("CARGO_PKG_VERSION"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );

        Ok(html)
    }

    fn generate_vulnerability_html(&self, report: &VulnerabilityReport) -> Result<String> {
        let vulnerabilities_rows: String = report.vulnerabilities.iter().map(|vuln| {
            let level_class = match vuln.level {
                crate::vulnerability::VulnerabilityLevel::Critical => "level-critical",
                crate::vulnerability::VulnerabilityLevel::High => "level-high",
                crate::vulnerability::VulnerabilityLevel::Medium => "level-medium",
                crate::vulnerability::VulnerabilityLevel::Low => "level-low",
                crate::vulnerability::VulnerabilityLevel::Info => "level-info",
            };
            
            format!(
                r#"<tr>
                    <td>{}</td>
                    <td><span class="{}">{:?}</span></td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>"#,
                vuln.port,
                level_class,
                vuln.level,
                vuln.service,
                vuln.title,
                vuln.evidence.chars().take(100).collect::<String>(),
                vuln.mitigation.chars().take(100).collect::<String>()
            )
        }).collect();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port-ZiLLA Vulnerability Report - {}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #e0e0e0; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #ff6b6b, #ff8e8e); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .card {{ background: #2d2d2d; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat-card {{ background: #3d3d3d; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-critical {{ border-left: 4px solid #dc3545; }}
        .stat-high {{ border-left: 4px solid #fd7e14; }}
        .stat-medium {{ border-left: 4px solid #ffc107; }}
        .stat-low {{ border-left: 4px solid #20c997; }}
        .stat-info {{ border-left: 4px solid #6c757d; }}
        .stat-number {{ font-size: 1.8em; font-weight: bold; }}
        .level-critical {{ color: #dc3545; font-weight: bold; }}
        .level-high {{ color: #fd7e14; font-weight: bold; }}
        .level-medium {{ color: #ffc107; font-weight: bold; }}
        .level-low {{ color: #20c997; }}
        .level-info {{ color: #6c757d; }}
        .vuln-table {{ width: 100%; border-collapse: collapse; }}
        .vuln-table th, .vuln-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
        .vuln-table th {{ background: #3d3d3d; color: #ffd700; }}
        .footer {{ text-align: center; margin-top: 40px; opacity: 0.7; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦖 Port-ZiLLA Vulnerability Report</h1>
            <div class="subtitle">Security Assessment Findings</div>
        </div>
        
        <div class="card">
            <h2>📈 Risk Summary</h2>
            <div class="stats">
                <div class="stat-card stat-critical">
                    <div class="stat-number">{}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card stat-high">
                    <div class="stat-number">{}</div>
                    <div>High</div>
                </div>
                <div class="stat-card stat-medium">
                    <div class="stat-number">{}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card stat-low">
                    <div class="stat-number">{}</div>
                    <div>Low</div>
                </div>
                <div class="stat-card stat-info">
                    <div class="stat-number">{}</div>
                    <div>Info</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>🎯 Assessment Details</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Target:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;">{} ({})</td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Overall Risk:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;"><span class="level-{}">{:?}</span></td></tr>
                <tr><td style="padding: 8px; border-bottom: 1px solid #444;"><strong>Risk Score:</strong></td><td style="padding: 8px; border-bottom: 1px solid #444;">{:.2}/10</td></tr>
                <tr><td style="padding: 8px;"><strong>Generated:</strong></td><td style="padding: 8px;">{}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>🔍 Vulnerabilities Found</h2>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Level</th>
                        <th>Service</th>
                        <th>Title</th>
                        <th>Evidence</th>
                        <th>Mitigation</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by Port-ZiLLA Enterprise v{} | {} | Contact: cyberzilla.systems@gmail.com
        </div>
    </div>
</body>
</html>"#,
            report.target,
            report.summary.critical_count,
            report.summary.high_count,
            report.summary.medium_count,
            report.summary.low_count,
            report.summary.info_count,
            report.target,
            report.target_ip,
            report.risk_assessment.overall_risk.to_string().to_lowercase(),
            report.risk_assessment.overall_risk,
            report.summary.risk_score,
            report.generated_at.to_rfc3339(),
            vulnerabilities_rows,
            env!("CARGO_PKG_VERSION"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );

        Ok(html)
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
              }
