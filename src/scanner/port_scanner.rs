 use super::models::{PortInfo, PortStatus, ServiceInfo, Protocol};
use crate::error::Result;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

#[async_trait]
pub trait Scanner: Send + Sync {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortInfo>;
    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Result<Vec<PortInfo>>;
}

pub struct PortScanner {
    timeout: Duration,
    max_concurrent: usize,
}

impl PortScanner {
    pub fn new(timeout: Duration, max_concurrent: usize) -> Self {
        Self {
            timeout,
            max_concurrent,
        }
    }
    
    async fn connect_with_timeout(&self, addr: SocketAddr) -> Result<bool> {
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                debug!("Port {} is OPEN on {}", addr.port(), addr.ip());
                Ok(true)
            }
            Ok(Err(e)) => {
                trace!("Port {} is CLOSED on {}: {}", addr.port(), addr.ip(), e);
                Ok(false)
            }
            Err(_) => {
                trace!("Port {} timeout on {}", addr.port(), addr.ip());
                Ok(false)
            }
        }
    }
}

#[async_trait]
impl Scanner for PortScanner {
    async fn scan_port(&self, target: IpAddr, port: u16) -> Result<PortInfo> {
        let addr = SocketAddr::new(target, port);
        let start_time = std::time::Instant::now();
        
        let is_open = self.connect_with_timeout(addr).await?;
        let response_time = start_time.elapsed();
        
        let status = if is_open { PortStatus::Open } else { PortStatus::Closed };
        
        // Basic service detection based on port number
        let service = if is_open {
            Some(detect_service_by_port(port))
        } else {
            None
        };

        Ok(PortInfo {
            port,
            status,
            service,
            banner: None,
            response_time: Some(response_time),
            protocol: Protocol::Tcp,
        })
    }

    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Result<Vec<PortInfo>> {
        use tokio::sync::Semaphore;
        use futures::stream::{self, StreamExt};
        
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut results = Vec::new();
        
        let stream = stream::iter(ports.iter().copied())
            .map(|port| {
                let target = target;
                let semaphore = Arc::clone(&semaphore);
                async move {
                    let _permit = semaphore.acquire().await?;
                    self.scan_port(target, port).await
                }
            })
            .buffer_unordered(self.max_concurrent);
        
        let mut stream = Box::pin(stream);
        while let Some(result) = stream.next().await {
            match result {
                Ok(port_info) => results.push(port_info),
                Err(e) => debug!("Port scan error: {}", e),
            }
        }
        
        Ok(results)
    }
}

fn detect_service_by_port(port: u16) -> ServiceInfo {
    let (name, product) = match port {
        21 => ("ftp", Some("FTP")),
        22 => ("ssh", Some("SSH")),
        23 => ("telnet", Some("Telnet")),
        25 => ("smtp", Some("SMTP")),
        53 => ("domain", Some("DNS")),
        80 => ("http", Some("HTTP")),
        110 => ("pop3", Some("POP3")),
        143 => ("imap", Some("IMAP")),
        443 => ("https", Some("HTTPS")),
        445 => ("microsoft-ds", Some("SMB")),
        993 => ("imaps", Some("IMAPS")),
        995 => ("pop3s", Some("POP3S")),
        1433 => ("ms-sql-s", Some("MSSQL")),
        3306 => ("mysql", Some("MySQL")),
        3389 => ("ms-wbt-server", Some("RDP")),
        5432 => ("postgresql", Some("PostgreSQL")),
        5900 => ("vnc", Some("VNC")),
        6379 => ("redis", Some("Redis")),
        8080 => ("http-proxy", Some("HTTP Proxy")),
        8443 => ("https-alt", Some("HTTPS")),
        27017 => ("mongodb", Some("MongoDB")),
        _ => ("unknown", None),
    };

    ServiceInfo {
        name: name.to_string(),
        version: None,
        product: product.map(|p| p.to_string()),
        extra_info: None,
        confidence: 80, // High confidence for well-known ports
    }
}

// Required for async trait
use std::sync::Arc;
