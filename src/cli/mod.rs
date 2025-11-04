pub mod args;
pub mod commands;

use clap::{Parser, Subcommand};
use std::net::IpAddr;

/// Enterprise Port Scanner - Professional security assessment tool
#[derive(Parser)]
#[command(
    name = "portscanner",
    version = "1.0.0",
    author = "Security Team",
    about = "Enterprise-grade port scanning and vulnerability assessment",
    long_about = "A comprehensive security tool for port scanning, service detection, and vulnerability assessment with enterprise features."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
    
    /// Enable debug output
    #[arg(short, long, global = true)]
    pub debug: bool,
    
    /// Configuration file path
    #[arg(short, long, global = true, default_value = "config/default.toml")]
    pub config: String,
}

#[derive(Subcommand)]
pub enum Command {
    /// Perform port scanning
    Scan(ScanArgs),
    
    /// Run vulnerability assessment
    Vulnerability(VulnerabilityArgs),
    
    /// View scan history
    History(HistoryArgs),
    
    /// Export scan results
    Export(ExportArgs),
    
    /// Manage configuration
    Config(ConfigArgs),
    
    /// Start web server
    Server(ServerArgs),
    
    /// Interactive mode
    Interactive,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Target IP address or hostname
    pub target: String,
    
    /// Scan type
    #[arg(short, long)]
    pub scan_type: Option<ScanType>,
    
    /// Custom port range (e.g., 1-1000)
    #[arg(short, long)]
    pub port_range: Option<PortRange>,
    
    /// Timeout in milliseconds
    #[arg(long, default_value = "100")]
    pub timeout: u64,
    
    /// Maximum concurrent threads
    #[arg(long, default_value = "200")]
    pub threads: usize,
    
    /// Enable stealth mode (SYN scan)
    #[arg(long)]
    pub stealth: bool,
    
    /// Enable UDP scanning
    #[arg(long)]
    pub udp: bool,
    
    /// Rate limit (scans per second)
    #[arg(long)]
    pub rate_limit: Option<u32>,
}

#[derive(clap::Args)]
pub struct VulnerabilityArgs {
    /// Target to scan
    pub target: Option<String>,
    
    /// Scan ID to analyze
    #[arg(long)]
    pub scan_id: Option<String>,
    
    /// Update vulnerability database
    #[arg(long)]
    pub update_db: bool,
    
    /// Output format for vulnerabilities
    #[arg(long, default_value = "table")]
    pub format: VulnOutputFormat,
}

#[derive(clap::Args)]
pub struct HistoryArgs {
    /// Number of scans to show
    #[arg(short, long, default_value = "10")]
    pub limit: usize,
    
    /// Show detailed information
    #[arg(short, long)]
    pub detailed: bool,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// Scan ID to export
    pub scan_id: String,
    
    /// Export format
    #[arg(short, long, default_value = "json")]
    pub format: ExportFormat,
    
    /// Output file path
    #[arg(short, long)]
    pub output_path: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
pub struct ConfigArgs {
    /// Configuration action
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(clap::Args)]
pub struct ServerArgs {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub host: IpAddr,
    
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    pub port: u16,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Edit configuration interactively
    Edit,
    /// Validate configuration
    Validate,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ScanType {
    /// Quick scan (top 100 ports)
    Quick,
    /// Standard scan (top 1000 ports)
    Standard,
    /// Full scan (all 65535 ports)
    Full,
    /// Custom port range
    Custom,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Json,
    Csv,
    Pdf,
    Html,
    Xml,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum VulnOutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(Clone, Debug)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl std::str::FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("Port range must be in format 'start-end'".to_string());
        }
        
        let start = parts[0].parse::<u16>()
            .map_err(|_| "Invalid start port".to_string())?;
        let end = parts[1].parse::<u16>()
            .map_err(|_| "Invalid end port".to_string())?;
            
        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }
        
        Ok(PortRange { start, end })
    }
}

// Implementation continues...
