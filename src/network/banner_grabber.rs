use crate::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub struct BannerGrabber {
    timeout: Duration,
    buffer_size: usize,
}

impl BannerGrabber {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            buffer_size: 1024,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn grab_banner(&self, target: IpAddr, port: u16) -> Result<String> {
        let addr = SocketAddr::new(target, port);
        
        debug!("Grabbing banner from {}:{}", target, port);
        
        match timeout(self.timeout, self.connect_and_read(&addr)).await {
            Ok(Ok(banner)) => {
                info!("Successfully grabbed banner from {}:{}", target, port);
                Ok(banner)
            }
            Ok(Err(e)) => {
                warn!("Failed to grab banner from {}:{} - {}", target, port, e);
                Err(e)
            }
            Err(_) => {
                warn!("Timeout grabbing banner from {}:{}", target, port);
                Err(Error::Network("Banner grab timeout".to_string()))
            }
        }
    }

    async fn connect_and_read(&self, addr: &SocketAddr) -> Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        
        // Set read timeout
        let _ = stream.try_readable().await?;
        
        let mut buffer = vec![0u8; self.buffer_size];
        let mut banner = String::new();
        
        // Try to read initial data
        match tokio::time::timeout(Duration::from_secs(2), stream.try_read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let data = &buffer[..n];
                if let Ok(text) = String::from_utf8(data.to_vec()) {
                    banner = self.clean_banner(&text);
                }
            }
            _ => {
                // Send protocol-specific probes for common services
                banner = self.send_probes(addr).await?;
            }
        }

        Ok(banner)
    }

    async fn send_probes(&self, addr: &SocketAddr) -> Result<String> {
        let port = addr.port();
        
        match port {
            // HTTP/HTTPS
            80 | 443 | 8080 | 8443 => self.probe_http(addr).await,
            // SSH
            22 => self.probe_ssh(addr).await,
            // FTP
            21 => self.probe_ftp(addr).await,
            // SMTP
            25 | 587 => self.probe_smtp(addr).await,
            // DNS
            53 => self.probe_dns(addr).await,
            // MySQL
            3306 => self.probe_mysql(addr).await,
            // PostgreSQL
            5432 => self.probe_postgresql(addr).await,
            // Redis
            6379 => self.probe_redis(addr).await,
            // MongoDB
            27017 => self.probe_mongodb(addr).await,
            // Default generic probe
            _ => self.probe_generic(addr).await,
        }
    }

    async fn probe_http(&self, addr: &SocketAddr) -> Result<String> {
        let probe = "GET / HTTP/1.0\r\n\r\n";
        self.send_probe_and_read(addr, probe.as_bytes()).await
    }

    async fn probe_ssh(&self, addr: &SocketAddr) -> Result<String> {
        // SSH servers typically send their banner immediately
        self.send_probe_and_read(addr, b"SSH-2.0-PortZiLLA\r\n").await
    }

    async fn probe_ftp(&self, addr: &SocketAddr) -> Result<String> {
        self.send_probe_and_read(addr, b"USER anonymous\r\n").await
    }

    async fn probe_smtp(&self, addr: &SocketAddr) -> Result<String> {
        self.send_probe_and_read(addr, b"EHLO example.com\r\n").await
    }

    async fn probe_dns(&self, addr: &SocketAddr) -> Result<String> {
        // Simple DNS query for google.com
        let probe = vec![
            0x00, 0x00, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // google.com query
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        self.send_probe_and_read(addr, &probe).await
    }

    async fn probe_mysql(&self, addr: &SocketAddr) -> Result<String> {
        // MySQL handshake initiation
        let probe = vec![0x0a, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x32, 0x38, 0x00];
        self.send_probe_and_read(addr, &probe).await
    }

    async fn probe_postgresql(&self, addr: &SocketAddr) -> Result<String> {
        // PostgreSQL startup message
        let probe = vec![
            0x00, 0x00, 0x00, 0x08, // Length
            0x04, 0xd2, 0x16, 0x2f, // Protocol version
        ];
        self.send_probe_and_read(addr, &probe).await
    }

    async fn probe_redis(&self, addr: &SocketAddr) -> Result<String> {
        self.send_probe_and_read(addr, b"PING\r\n").await
    }

    async fn probe_mongodb(&self, addr: &SocketAddr) -> Result<String> {
        // MongoDB OP_QUERY
        let probe = vec![
            0x3a, 0x00, 0x00, 0x00, // Message length
            0x00, 0x00, 0x00, 0x00, // Request ID
            0x00, 0x00, 0x00, 0x00, // Response To
            0xd4, 0x07, 0x00, 0x00, // OP_QUERY
            0x00, 0x00, 0x00, 0x00, // Flags
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // admin.$cmd
            0x00, 0x00, 0x00, 0x00, // Number to skip
            0x01, 0x00, 0x00, 0x00, // Number to return
            0x18, 0x00, 0x00, 0x00, // Document length
            0x01, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, // isMaster: 1
        ];
        self.send_probe_and_read(addr, &probe).await
    }

    async fn probe_generic(&self, addr: &SocketAddr) -> Result<String> {
        // Generic probe - just try to read whatever the service sends
        self.send_probe_and_read(addr, b"\r\n\r\n").await
    }

    async fn send_probe_and_read(&self, addr: &SocketAddr, probe: &[u8]) -> Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        
        // Send probe
        stream.write_all(probe).await?;
        
        // Read response
        let mut buffer = vec![0u8; self.buffer_size];
        let n = match timeout(Duration::from_secs(2), stream.try_read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        if n > 0 {
            let data = &buffer[..n];
            if let Ok(text) = String::from_utf8(data.to_vec()) {
                Ok(self.clean_banner(&text))
            } else {
                Ok(format!("[Binary data: {} bytes]", n))
            }
        } else {
            Ok("[No response]".to_string())
        }
    }

    fn clean_banner(&self, banner: &str) -> String {
        banner
            .trim()
            .replace("\r\n", " | ")
            .replace('\n', " | ")
            .replace('\r', " | ")
            .chars()
            .take(500) // Limit banner length
            .collect()
    }
}

impl Default for BannerGrabber {
    fn default() -> Self {
        Self::new()
    }
}

use tokio::io::{AsyncWriteExt, AsyncReadExt};
