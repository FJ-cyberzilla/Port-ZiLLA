pub mod terminal;
pub mod progress;
pub mod dashboard;

pub use terminal::TerminalUI;
pub use progress::ProgressBar;
pub use dashboard::Dashboard;

use colored::*;

pub struct PortZiLLAUI;

impl PortZiLLAUI {
    pub fn print_banner() {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".bright_yellow());
        println!("{}", "║                            PORT-ZILLA ENTERPRISE                           ║".bright_yellow().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".bright_yellow());
        println!();
        
        let ascii_art = r#"
    .########...#######..########..########.########.####.##.......##..........###...
    .##.....##.##.....##.##.....##....##.........##...##..##.......##.........##.##..
    .##.....##.##.....##.##.....##....##........##....##..##.......##........##...##.
    .########..##.....##.########.....##.......##.....##..##.......##.......##.....##
    .##........##.....##.##...##......##......##......##..##.......##.......#########
    .##........##.....##.##....##.....##.....##.......##..##.......##.......##.....##
    .##.........#######..##.....##....##....########.####.########.########.##.....##
        "#.bright_yellow();
        
        println!("{}", ascii_art);
        println!();
        println!("{}", "           Enterprise-Level Port Scanner & Vulnerability Detector".bright_cyan());
        println!("{}", "                          Version 1.0.0 - 2024".bright_cyan());
        println!("{}", "                     For Authorized Security Testing Only".bright_red().bold());
        println!();
        println!("{}", "══════════════════════════════════════════════════════════════════════════════".bright_yellow());
        println!();
    }

    pub fn print_menu() {
        println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_yellow());
        println!("{}", "║                      MAIN MENU                       ║".bright_yellow().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_yellow());
        println!();
        
        let menu_items = vec![
            ("[1]", "Quick Scan (Top 100 Ports)", "🚀"),
            ("[2]", "Standard Scan (Top 1000 Ports)", "📊"),
            ("[3]", "Full Scan (All 65535 Ports)", "🔍"),
            ("[4]", "Custom Port Range Scan", "🎯"),
            ("[5]", "Vulnerability Assessment Only", "🛡️"),
            ("[6]", "Export Last Scan to JSON", "💾"),
            ("[7]", "Export Last Scan to CSV", "📄"),
            ("[8]", "View Scan History", "📋"),
            ("[9]", "Configuration Settings", "⚙️"),
            ("[10]", "About / Help", "❓"),
            ("[0]", "Exit", "👋"),
        ];

        for (num, desc, icon) in menu_items {
            println!("  {} {} {}", 
                num.bright_cyan().bold(), 
                icon.bright_green(),
                desc.bright_white()
            );
        }
        
        println!();
        println!("{}", "══════════════════════════════════════════════════════════".bright_yellow());
        println!();
    }

    pub fn print_help() {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_yellow());
        println!("{}", "║                      HELP & USAGE                      ║".bright_yellow().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_yellow());
        println!();
        
        let help_sections = vec![
            ("Quick Start", "Select option 1-4 to start scanning. Enter target IP when prompted."),
            ("Target Format", "Use IP addresses (192.168.1.1) or hostnames (example.com)"),
            ("Scan Types", "Quick: Common ports | Standard: 1000 ports | Full: All ports"),
            ("Vulnerability Scan", "Automatically checks for common security issues"),
            ("Export Results", "Save scans in JSON, CSV, or PDF format for reporting"),
            ("Configuration", "Adjust timeouts, threads, and other settings in config"),
        ];

        for (title, content) in help_sections {
            println!("  {} {}", "►".bright_green(), title.bright_cyan().bold());
            println!("    {}", content.bright_white());
            println!();
        }
        
        println!("{}", "Need more help? Visit: https://github.com/FJ-cyberzilla/Port-ZiLLA".bright_blue());
        println!("{}", "Contact: cyberzilla.systems@gmail.com".bright_blue());
        println!();
    }

    pub fn print_scan_start(target: &str, scan_type: &str) {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_yellow());
        println!("{}", "║                      SCAN STARTED                      ║".bright_yellow().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_yellow());
        println!();
        println!("  {}  {}", "🎯 Target:".bright_cyan(), target.bright_white().bold());
        println!("  {}  {}", "📊 Type:".bright_cyan(), scan_type.bright_white());
        println!("  {}  {}", "⏰ Started:".bright_cyan(), chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string().bright_white());
        println!();
        println!("{}", "Scanning in progress...".bright_yellow().bold());
        println!();
    }

    pub fn print_scan_complete(open_ports: usize, duration: std::time::Duration) {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_green());
        println!("{}", "║                      SCAN COMPLETE                     ║".bright_green().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_green());
        println!();
        println!("  {}  {}", "✅ Open Ports Found:".bright_cyan(), open_ports.to_string().bright_green().bold());
        println!("  {}  {}", "⏱️  Duration:".bright_cyan(), format_duration(duration).bright_white());
        println!("  {}  {}", "🏁 Completed:".bright_cyan(), chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string().bright_white());
        println!();
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs > 60 {
        format!("{:.2} minutes", secs as f64 / 60.0)
    } else if secs > 1 {
        format!("{:.2} seconds", secs as f64)
    } else {
        format!("{} ms", duration.as_millis())
    }
}
