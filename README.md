# 🦖 Port-ZiLLA Enterprise

**Enterprise-grade port scanner and vulnerability assessment tool**

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-brightgreen)](SECURITY.md)
[![CodeQL Analysis](https://github.com/FJ-cyberzilla/Port-ZiLLA/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/FJ-cyberzilla/Port-ZiLLA/actions/workflows/codeql-analysis.yml)
## 🚀 Features

### Core Scanning
- **Multi-threaded port scanning** with configurable timeouts
- **Multiple scan types**: Quick (100 ports), Standard (1000 ports), Full (all ports), Custom ranges
- **Service detection** with banner grabbing
- **OS fingerprinting** and traceroute capabilities
- **SYN and UDP scanning** (with appropriate privileges)

### Security Assessment
- **Vulnerability detection** with CVE database integration
- **Risk assessment** with CVSS scoring
- **Security recommendations** with mitigation steps
- **Comprehensive reporting** with business impact analysis

### Enterprise Ready
- **SQL database** with persistent storage
- **REST API** with authentication and rate limiting
- **Multiple export formats**: JSON, CSV, HTML, PDF, XML
- **Configuration management** with environment support
- **Docker containerization** for easy deployment

### Professional UI
- **Interactive terminal interface** with progress bars
- **Color-coded output** with Port-ZiLLA branding
- **Real-time progress updates** during scans
- **Comprehensive help system**

## 📦 Installation

### Prerequisites
- Rust 1.70+ ([install](https://rustup.rs/))
- SQLite development libraries

### Quick Start
```bash
# Clone the repository
git clone https://github.com/FJ-cyberzilla/Port-ZiLLA.git
cd Port-ZiLLA

# Run setup script
./scripts/setup.sh

# Start interactive mode
cargo run -- interactive
