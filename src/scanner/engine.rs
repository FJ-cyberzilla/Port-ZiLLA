use super::{PortScanner, SynScanner, UdpScanner, ScanResult, ScanType, ScanConfig, ScanProgress, CommonPorts};
use crate::error::{Error, Result};
use crate::network::{BannerGrabber, ServiceDetector, OsDetector};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, debug, warn};

pub struct ScanEngine {
    config: ScanConfig,
    tcp_scanner: Arc<PortScanner>,
    syn_scanner: Option<Arc<SynScanner>>,
    udp_scanner: Option<Arc<UdpScanner>>,
    banner_grabber: Arc<BannerGrabber>,
    service_detector: Arc<ServiceDetector>,
    os_detector: Arc<OsDetector>,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Result<Self> {
        let tcp_scanner = Arc::new(PortScanner::new(config.timeout, config.max_concurrent_tasks));
        
        let syn_scanner = if config.stealth_mode {
            Some(Arc::new(SynScanner::new(config.timeout, config.max_concurrent_tasks)?))
        } else {
            None
        };

        let udp_scanner = Some(Arc::new(UdpScanner::new(config.timeout, config.max_concurrent_tasks)?));

        let banner_grabber = Arc::new(BannerGrabber::new());
        let service_detector = Arc::new(ServiceDetector::new());
        let os_detector = Arc::new(OsDetector::new());

        Ok(Self {
            config,
            tcp_scanner,
            syn_scanner,
            udp_scanner,
            banner_grabber,
            service_detector,
            os_detector,
        })
    }

    pub async fn scan(&self, target: &str, scan_type: ScanType) -> Result<ScanResult> {
        let target_ip: IpAddr = target.parse()
            .map_err(|e| Error::TargetResolution(e.to_string()))?;

        info!("Starting {} scan for {}", scan_type, target);

        let mut scan_result = ScanResult::new(target.to_string(), target_ip, scan_type.clone());

        // Get ports to scan based on scan type
        let ports = self.get_ports_to_scan(&scan_type);
        
        // Perform the actual port scanning
        let open_ports = self.scan_ports(target_ip, &ports).await?;
        
        // Enhanced service detection for open ports
        let enhanced_ports = self.enhance_scan_results(target_ip, open_ports).await?;
        
        // Add results to scan
        for port_info in enhanced_ports {
            scan_result.add_open_port(port_info);
        }

        // OS detection if enabled
        if self.config.enable_os_detection {
            if let Ok(os_info) = self.os_detector.detect_os(target_ip).await {
                scan_result.metadata.os_detection = Some(os_info);
            }
        }

        scan_result.finalize();

        info!(
            "Scan completed: {} open ports found in {:?}",
            scan_result.open_ports.len(),
            scan_result.duration()
        );

        Ok(scan_result)
    }

    pub async fn scan_with_progress(
        &self, 
        target: &str, 
        scan_type: ScanType,
        progress_tx: mpsc::Sender<ScanProgress>
    ) -> Result<ScanResult> {
        let target_ip: IpAddr = target.parse()
            .map_err(|e| Error::TargetResolution(e.to_string()))?;

        let mut scan_result = ScanResult::new(target.to_string(), target_ip, scan_type.clone());
        let ports = self.get_ports_to_scan(&scan_type);
        let total_ports = ports.len() as u16;

        let (result_tx, _) = mpsc::channel(1000);
        let progress_tx = Arc::new(RwLock::new(progress_tx));

        // Scan ports with progress reporting
        let open_ports = self.scan_ports_with_progress(
            target_ip, 
            &ports, 
            result_tx, 
            Arc::clone(&progress_tx),
            total_ports
        ).await?;

        // Collect results
        let mut enhanced_ports = Vec::new();
        for port_info in open_ports {
            enhanced_ports.push(port_info);
        }

        // Enhance with service detection
        let enhanced_ports = self.enhance_scan_results(target_ip, enhanced_ports).await?;
        
        for port_info in enhanced_ports {
            scan_result.add_open_port(port_info);
        }

        scan_result.finalize();
        Ok(scan_result)
    }

    fn get_ports_to_scan(&self, scan_type: &ScanType) -> Vec<u16> {
        match scan_type {
            ScanType::Quick => CommonPorts::top_100(),
            ScanType::Standard => CommonPorts::top_1000(),
            ScanType::Full => CommonPorts::all_ports(),
            ScanType::CustomRange(start, end) => (*start..=*end).collect(),
            ScanType::Targeted(ports) => ports.clone(),
        }
    }

    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Result<Vec<super::PortInfo>> {
        let scanner = if self.config.stealth_mode {
            self.syn_scanner.as_ref().unwrap_or(&self.tcp_scanner)
        } else {
            &self.tcp_scanner
        };

        let mut open_ports = Vec::new();

        for &port in ports {
            match scanner.scan_port(target, port).await {
                Ok(port_info) => {
                    if port_info.status == super::PortStatus::Open {
                        open_ports.push(port_info);
                    }
                }
                Err(e) => {
                    warn!("Failed to scan port {}: {}", port, e);
                }
            }
        }

        Ok(open_ports)
    }

    async fn scan_ports_with_progress(
        &self,
        target: IpAddr,
        ports: &[u16],
        result_tx: mpsc::Sender<super::PortInfo>,
        progress_tx: Arc<RwLock<mpsc::Sender<ScanProgress>>>,
        total_ports: u16,
    ) -> Result<Vec<super::PortInfo>> {
        use tokio::sync::Semaphore;
        use futures::stream::{self, StreamExt};
        use std::time::Instant;

        let start_time = Instant::now();
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_tasks));
        let mut open_ports = Vec::new();
        let mut completed = 0u16;

        let stream = stream::iter(ports.iter().copied())
            .map(|port| {
                let target = target;
                let semaphore = Arc::clone(&semaphore);
                let result_tx = result_tx.clone();
                let progress_tx = Arc::clone(&progress_tx);
                
                async move {
                    let _permit = semaphore.acquire().await?;
                    let scanner = if self.config.stealth_mode {
                        self.syn_scanner.as_ref().unwrap_or(&self.tcp_scanner)
                    } else {
                        &self.tcp_scanner
                    };

                    let result = scanner.scan_port(target, port).await;
                    
                    // Send progress update
                    completed += 1;
                    let progress = ScanProgress {
                        current_port: port,
                        total_ports,
                        percentage: (completed as f64 / total_ports as f64) * 100.0,
                        open_ports_found: open_ports.len() as u16,
                        elapsed_time: start_time.elapsed(),
                        estimated_remaining: calculate_remaining_time(start_time.elapsed(), completed, total_ports),
                    };

                    if let Ok(tx) = progress_tx.try_write() {
                        let _ = tx.send(progress).await;
                    }

                    if let Ok(port_info) = &result {
                        if port_info.status == super::PortStatus::Open {
                            let _ = result_tx.send(port_info.clone()).await;
                        }
                    }

                    result
                }
            })
            .buffer_unordered(self.config.max_concurrent_tasks);

        let mut stream = Box::pin(stream);
        while let Some(result) = stream.next().await {
            if let Ok(port_info) = result {
                if port_info.status == super::PortStatus::Open {
                    open_ports.push(port_info);
                }
            }
        }

        Ok(open_ports)
    }

    async fn enhance_scan_results(
        &self, 
        target: IpAddr, 
        mut port_infos: Vec<super::PortInfo>
    ) -> Result<Vec<super::PortInfo>> {
        if !self.config.enable_service_detection && !self.config.enable_banner_grabbing {
            return Ok(port_infos);
        }

        let mut enhanced_ports = Vec::new();

        for mut port_info in port_infos {
            // Service detection
            if self.config.enable_service_detection {
                if let Ok(service) = self.service_detector.detect_service(target, port_info.port).await {
                    port_info.service = Some(service);
                }
            }

            // Banner grabbing
            if self.config.enable_banner_grabbing {
                if let Ok(banner) = self.banner_grabber.grab_banner(target, port_info.port).await {
                    port_info.banner = Some(banner);
                }
            }

            enhanced_ports.push(port_info);
        }

        Ok(enhanced_ports)
    }
}

fn calculate_remaining_time(elapsed: std::time::Duration, completed: u16, total: u16) -> std::time::Duration {
    if completed == 0 {
        return std::time::Duration::from_secs(0);
    }
    
    let time_per_port = elapsed.as_secs_f64() / completed as f64;
    let remaining_ports = (total - completed) as f64;
    std::time::Duration::from_secs_f64(time_per_port * remaining_ports)
      }
