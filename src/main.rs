use portscanner_enterprise::{
    cli::{Cli, Command},
    config::Settings,
    error::{Error, Result},
    storage::ScanRepository,
    utils::setup_logging,
};
use tracing::{error, info, Level};
use std::process;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging and error handling
    setup_logging(Level::INFO)?;
    
    // Initialize panic hook for better error reporting
    initialize_panic_hook();
    
    info!("🚀 Starting PortScanner Enterprise v1.0.0");
    
    if let Err(e) = run().await {
        error!("❌ Application error: {}", e);
        eprintln!("Error: {}", e);
        process::exit(1);
    }
    
    info!("👋 PortScanner Enterprise shutdown complete");
    Ok(())
}

async fn run() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Load configuration
    let settings = Settings::new()?;
    info!("📋 Configuration loaded successfully");
    
    // Initialize database connection
    let repository = ScanRepository::new(&settings.database.connection_string).await?;
    info!("💾 Database connection established");
    
    // Execute the requested command
    match cli.command {
        Command::Scan(scan_args) => {
            execute_scan(scan_args, &settings, &repository).await?;
        }
        Command::Vulnerability(vuln_args) => {
            execute_vulnerability_scan(vuln_args, &settings, &repository).await?;
        }
        Command::History(history_args) => {
            show_scan_history(history_args, &repository).await?;
        }
        Command::Export(export_args) => {
            export_scan_results(export_args, &repository).await?;
        }
        Command::Config(config_args) => {
            manage_configuration(config_args, &settings).await?;
        }
        Command::Server(server_args) => {
            start_web_server(server_args, &settings, repository).await?;
        }
        Command::Interactive => {
            start_interactive_mode(&settings, repository).await?;
        }
    }
    
    Ok(())
}

async fn execute_scan(
    scan_args: crate::cli::ScanArgs,
    settings: &Settings,
    repository: &ScanRepository,
) -> Result<()> {
    use portscanner_enterprise::scanner::{ScanEngine, ScanType};
    
    info!("🎯 Starting scan for target: {}", scan_args.target);
    
    // Validate target and parameters
    validate_scan_parameters(&scan_args, settings)?;
    
    // Create scan engine
    let engine = ScanEngine::new(settings)?;
    
    // Determine scan type
    let scan_type = match (scan_args.scan_type, scan_args.port_range) {
        (Some(scan_type), _) => scan_type,
        (None, Some(range)) => ScanType::CustomRange(range.start, range.end),
        (None, None) => ScanType::Standard, // Default to standard scan
    };
    
    // Execute scan
    let scan_result = engine
        .scan(&scan_args.target, scan_type)
        .await?;
    
    info!(
        "✅ Scan completed: {} open ports found", 
        scan_result.open_ports.len()
    );
    
    // Save to database
    let scan_id = repository.save_scan(&scan_result).await?;
    info!("💾 Scan saved with ID: {}", scan_id);
    
    // Display results
    crate::ui::display_scan_results(&scan_result)?;
    
    // Auto-export if configured
    if settings.export.auto_export {
        crate::export::auto_export(&scan_result, &settings.export).await?;
    }
    
    Ok(())
}

async fn execute_vulnerability_scan(
    vuln_args: crate::cli::VulnerabilityArgs,
    settings: &Settings,
    repository: &ScanRepository,
) -> Result<()> {
    use portscanner_enterprise::vulnerability::VulnerabilityScanner;
    
    info!("🔍 Starting vulnerability assessment");
    
    let scanner = VulnerabilityScanner::new(settings)?;
    
    let vulnerability_report = if let Some(scan_id) = vuln_args.scan_id {
        // Run vulnerability scan on existing scan results
        scanner.analyze_existing_scan(scan_id).await?
    } else if let Some(target) = vuln_args.target {
        // Run new scan with vulnerability assessment
        scanner.scan_and_analyze(&target).await?
    } else {
        return Err(Error::Validation("Either scan_id or target must be provided".into()));
    };
    
    // Save vulnerability report
    repository.save_vulnerability_report(&vulnerability_report).await?;
    
    // Display results
    crate::ui::display_vulnerability_report(&vulnerability_report)?;
    
    Ok(())
}

async fn show_scan_history(
    history_args: crate::cli::HistoryArgs,
    repository: &ScanRepository,
) -> Result<()> {
    let scans = repository.get_scan_history(history_args.limit).await?;
    crate::ui::display_scan_history(&scans, history_args.detailed)?;
    Ok(())
}

async fn export_scan_results(
    export_args: crate::cli::ExportArgs,
    repository: &ScanRepository,
) -> Result<()> {
    use portscanner_enterprise::export::{ExportFormat, Exporter};
    
    let scan = repository.get_scan(export_args.scan_id).await?;
    let exporter = Exporter::new(export_args.format);
    
    let output_path = exporter.export(&scan, &export_args.output_path).await?;
    info!("📤 Scan exported to: {}", output_path.display());
    
    Ok(())
}

async fn manage_configuration(
    config_args: crate::cli::ConfigArgs,
    settings: &Settings,
) -> Result<()> {
    match config_args.action {
        crate::cli::ConfigAction::Show => {
            crate::ui::display_configuration(settings)?;
        }
        crate::cli::ConfigAction::Edit => {
            crate::ui::edit_configuration_interactive(settings).await?;
        }
        crate::cli::ConfigAction::Validate => {
            crate::config::validate_configuration(settings)?;
            info("✅ Configuration is valid");
        }
    }
    
    Ok(())
}

async fn start_web_server(
    server_args: crate::cli::ServerArgs,
    settings: &Settings,
    repository: ScanRepository,
) -> Result<()> {
    use portscanner_enterprise::web::Server;
    
    info!("🌐 Starting web server on {}:{}", server_args.host, server_args.port);
    
    let server = Server::new(settings, repository);
    server.run(server_args.host, server_args.port).await?;
    
    Ok(())
}

async fn start_interactive_mode(
    settings: &Settings,
    repository: ScanRepository,
) -> Result<()> {
    info!("🎮 Starting interactive mode");
    crate::ui::interactive::run(settings, repository).await?;
    Ok(())
}

fn validate_scan_parameters(scan_args: &crate::cli::ScanArgs, settings: &Settings) -> Result<()> {
    use std::net::IpAddr;
    
    // Validate target format
    if scan_args.target.parse::<IpAddr>().is_err() && scan_args.target.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(Error::Validation(format!("Invalid target format: {}", scan_args.target)));
    }
    
    // Check if target is allowed
    if !settings.security.is_target_allowed(&scan_args.target) {
        return Err(Error::Security(format!("Target {} is not in allowed list", scan_args.target)));
    }
    
    // Validate port range if provided
    if let Some(range) = &scan_args.port_range {
        if range.start > range.end {
            return Err(Error::Validation("Invalid port range: start must be <= end".into()));
        }
        
        let port_count = (range.end - range.start) + 1;
        if port_count > settings.security.max_ports_per_scan {
            return Err(Error::Validation(format!(
                "Port range too large: {} ports (max: {})", 
                port_count, settings.security.max_ports_per_scan
            )));
        }
    }
    
    Ok(())
}

fn initialize_panic_hook() {
    let original_hook = std::panic::take_hook();
    
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("💥 Critical application panic:");
        
        // Log the panic information
        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            error!("Panic message: {}", s);
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            error!("Panic message: {}", s);
        }
        
        // Log location if available
        if let Some(location) = panic_info.location() {
            error!("Panic occurred in file '{}' at line {}", location.file(), location.line());
        }
        
        // Call original hook
        original_hook(panic_info);
        
        // Exit with error code
        std::process::exit(1);
    }));
}

// Utility function for info messages
fn info(message: &str) {
    println!("{}", message);
    tracing::info!("{}", message);
  }
