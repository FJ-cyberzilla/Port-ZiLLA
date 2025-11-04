use crate::error::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub confidence: u8,
}

pub struct ServiceDetector {
    banner_grabber: super::BannerGrabber,
    service_patterns: HashMap<&'static str, Vec<&'static str>>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        let mut service_patterns = HashMap::new();
        
        // SSH patterns
        service_patterns.insert("ssh", vec!["SSH", "OpenSSH"]);
        // HTTP patterns
        service_patterns.insert("http", vec!["HTTP", "Apache", "nginx", "IIS", "Server:"]);
        // FTP patterns
        service_patterns.insert("ftp", vec!["FTP", "220", "vsFTPd", "ProFTPD"]);
        // SMTP patterns
        service_patterns.insert("smtp", vec!["SMTP", "ESMTP", "Postfix", "Sendmail", "Exim"]);
        // DNS patterns
        service_patterns.insert("dns", vec!["DNS", "BIND"]);
        // MySQL patterns
        service_patterns.insert("mysql", vec!["MySQL", "mariadb"]);
        // PostgreSQL patterns
        service_patterns.insert("postgresql", vec!["PostgreSQL"]);
        // Redis patterns
        service_patterns.insert("redis", vec!["REDIS", "Redis"]);
        // MongoDB patterns
        service_patterns.insert("mongodb", vec!["MongoDB"]);
        // RDP patterns
        service_patterns.insert("rdp", vec!["Microsoft Terminal Services"]);
        // VNC patterns
        service_patterns.insert("vnc", vec!["RFB", "VNC"]);

        Self {
            banner_grabber: super::BannerGrabber::new(),
            service_patterns,
        }
    }

    pub async fn detect_service(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
        debug!("Detecting service on {}:{}", target, port);
        
        // First, try to get a banner
        let banner = match timeout(Duration::from_secs(3), self.banner_grabber.grab_banner(target, port)).await {
            Ok(Ok(banner)) if !banner.is_empty() && banner != "[No response]" => Some(banner),
            _ => None,
        };

        // If we have a banner, analyze it
        if let Some(banner) = banner {
            self.analyze_banner(&banner, port).await
        } else {
            // Fall back to port-based detection
            self.detect_by_port(port).await
        }
    }

    async fn analyze_banner(&self, banner: &str, port: u16) -> Result<ServiceInfo> {
        let banner_lower = banner.to_lowercase();
        
        for (service_name, patterns) in &self.service_patterns {
            for pattern in patterns {
                if banner_lower.contains(&pattern.to_lowercase()) {
                    let (version, product) = self.extract_version_and_product(banner, service_name);
                    
                    info!("Detected service: {} on port {} (confidence: 90)", service_name, port);
                    
                    return Ok(ServiceInfo {
                        name: service_name.to_string(),
                        version,
                        product,
                        extra_info: Some(banner.chars().take(100).collect()),
                        confidence: 90,
                    });
                }
            }
        }

        // If no specific pattern matched, use port-based detection but with lower confidence
        let mut port_based = self.detect_by_port(port).await;
        port_based.confidence = 60; // Lower confidence for port-based without banner confirmation
        port_based.extra_info = Some(format!("Banner: {}", banner.chars().take(100).collect::<String>()));
        
        Ok(port_based)
    }

    async fn detect_by_port(&self, port: u16) -> Result<ServiceInfo> {
        let (name, product) = match port {
            21 => ("ftp", Some("FTP")),
            22 => ("ssh", Some("SSH")),
            23 => ("telnet", Some("Telnet")),
            25 => ("smtp", Some("SMTP")),
            53 => ("dns", Some("DNS")),
            80 => ("http", Some("HTTP")),
            110 => ("pop3", Some("POP3")),
            143 => ("imap", Some("IMAP")),
            443 => ("https", Some("HTTPS")),
            445 => ("smb", Some("SMB")),
            993 => ("imaps", Some("IMAPS")),
            995 => ("pop3s", Some("POP3S")),
            1433 => ("mssql", Some("Microsoft SQL Server")),
            3306 => ("mysql", Some("MySQL")),
            3389 => ("rdp", Some("Remote Desktop")),
            5432 => ("postgresql", Some("PostgreSQL")),
            5900 => ("vnc", Some("VNC")),
            6379 => ("redis", Some("Redis")),
            8080 => ("http", Some("HTTP Proxy")),
            8443 => ("https", Some("HTTPS Alternative")),
            27017 => ("mongodb", Some("MongoDB")),
            _ => ("unknown", None),
        };

        Ok(ServiceInfo {
            name: name.to_string(),
            version: None,
            product: product.map(|p| p.to_string()),
            extra_info: None,
            confidence: 80, // High confidence for well-known ports
        })
    }

    fn extract_version_and_product(&self, banner: &str, service: &str) -> (Option<String>, Option<String>) {
        let banner_lower = banner.to_lowercase();
        let mut version = None;
        let mut product = None;

        match service {
            "ssh" => {
                if banner_lower.contains("openssh") {
                    product = Some("OpenSSH".to_string());
                    version = self.extract_version(banner, r"OpenSSH[_\-\s]?(\d+\.\d+(?:\.\d+)?)");
                }
            }
            "http" => {
                if banner_lower.contains("apache") {
                    product = Some("Apache".to_string());
                    version = self.extract_version(banner, r"Apache/(\d+\.\d+(?:\.\d+)?)");
                } else if banner_lower.contains("nginx") {
                    product = Some("nginx".to_string());
                    version = self.extract_version(banner, r"nginx/(\d+\.\d+(?:\.\d+)?)");
                } else if banner_lower.contains("microsoft-iis") || banner_lower.contains("iis") {
                    product = Some("IIS".to_string());
                    version = self.extract_version(banner, r"Microsoft-IIS/(\d+\.\d+)");
                }
            }
            "ftp" => {
                if banner_lower.contains("vsftpd") {
                    product = Some("vsFTPd".to_string());
                    version = self.extract_version(banner, r"vsFTPd\s+(\d+\.\d+(?:\.\d+)?)");
                } else if banner_lower.contains("proftpd") {
                    product = Some("ProFTPD".to_string());
                }
            }
            _ => {}
        }

        (version, product)
    }

    fn extract_version(&self, text: &str, pattern: &str) -> Option<String> {
        use regex::Regex;
        
        Regex::new(pattern)
            .ok()
            .and_then(|re| re.captures(text))
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new()
    }
                      }
