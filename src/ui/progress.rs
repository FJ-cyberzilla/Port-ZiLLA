use std::time::Duration;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

pub struct AnimatedProgress {
    multi: MultiProgress,
    main_bar: ProgressBar,
    port_bar: Option<ProgressBar>,
}

impl AnimatedProgress {
    pub fn new(total_ports: u64) -> Self {
        let multi = MultiProgress::new();
        
        // Main progress bar
        let main_bar = ProgressBar::new(total_ports);
        main_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} {msg} {wide_bar:.cyan/blue} {pos}/{len} ports ({eta})")
                .unwrap()
                .progress_chars("█▓▒░ ")
        );
        main_bar.set_message("Port-ZiLLA Scanning".to_string());

        // Port-specific progress bar (added when needed)
        let port_bar = None;

        Self {
            multi,
            main_bar,
            port_bar,
        }
    }

    pub fn update_main(&self, current: u64, message: &str) {
        self.main_bar.set_position(current);
        self.main_bar.set_message(message.to_string());
    }

    pub fn add_port_progress(&mut self, port: u16) {
        if let Some(ref bar) = self.port_bar {
            bar.finish_and_clear();
        }

        let bar = ProgressBar::new(100);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.yellow} Scanning port {msg} {wide_bar:.yellow/red} {pos}%")
                .unwrap()
                .progress_chars("█▓▒░ ")
        );
        bar.set_message(port.to_string());
        
        let bar = self.multi.add(bar);
        self.port_bar = Some(bar);
    }

    pub fn update_port_progress(&self, progress: u64) {
        if let Some(ref bar) = self.port_bar {
            bar.set_position(progress);
        }
    }

    pub fn finish_port(&self) {
        if let Some(ref bar) = self.port_bar {
            bar.finish_with_message("✓ Complete");
        }
    }

    pub fn finish_all(&self) {
        self.main_bar.finish_with_message("🎉 Scan Complete!");
        if let Some(ref bar) = self.port_bar {
            bar.finish_and_clear();
        }
    }

    pub fn print_animated_banner(&self) {
        let frames = vec![
            r#"
    ██████╗  ██████╗ ██████╗ ████████╗    ███████╗██╗██╗  ██╗██╗      █████╗ 
    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██║██║  ██║██║     ██╔══██╗
    ██████╔╝██║   ██║██████╔╝   ██║       █████╗  ██║███████║██║     ███████║
    ██╔═══╝ ██║   ██║██╔══██╗   ██║         ██╔══╝  ██║██╔══██║██║     ██╔══██║
    ██║     ╚██████╔╝██║  ██║   ██║        ███████╗██║██║  ██║███████╗██║  ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
            "#,
            r#"
    ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██╗██╗  ██╗██╗      █████╗ 
    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██║██║  ██║██║     ██╔══██╗
    ██████╔╝██║   ██║██████╔╝   ██║        ███████╗██║███████║██║     ███████║
    ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║ ██║██╔══██║██║     ██╔══██║
    ██║     ╚██████╔╝██║  ██║   ██║        ███████║██║██║  ██║███████╗██║  ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝        ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
            "#,
        ];

        for frame in frames.iter().cycle().take(10) {
            println!("{}", frame.bright_yellow());
            std::thread::sleep(Duration::from_millis(200));
            print!("{esc}[2J{esc}[1;1H", esc = 27 as char); // Clear screen
        }
    }
}

impl Drop for AnimatedProgress {
    fn drop(&mut self) {
        self.finish_all();
    }
}
