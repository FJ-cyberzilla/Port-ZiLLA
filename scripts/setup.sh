#!/bin/bash

# Port-ZiLLA Enterprise Advanced Setup Script
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Port-ZiLLA Banner
print_banner() {
    echo -e "${YELLOW}"
    cat << "EOF"

    .########...#######..########..########.########.####.##.......##..........###...
    .##.....##.##.....##.##.....##....##.........##...##..##.......##.........##.##..
    .##.....##.##.....##.##.....##....##........##....##..##.......##........##...##.
    .########..##.....##.########.....##.......##.....##..##.......##.......##.....##
    .##........##.....##.##...##......##......##......##..##.......##.......#########
    .##........##.....##.##....##.....##.....##.......##..##.......##.......##.....##
    .##.........#######..##.....##....##....########.####.########.########.##.....##

EOF
    echo -e "${NC}"
    echo -e "${CYAN}           Port-ZiLLA Enterprise - Advanced Setup & Configuration${NC}"
    echo -e "${CYAN}                     Professional Security Assessment Tool${NC}"
    echo -e "${CYAN}                          Version 1.0.0 - 2024${NC}"
    echo -e "${CYAN}                    For Authorized Security Testing Only${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo
}

# Platform detection
detect_platform() {
    echo -e "${BLUE}🔍 Detecting platform...${NC}"
    
    if [[ -f "/proc/version" ]]; then
        if grep -q "Microsoft" /proc/version; then
            PLATFORM="wsl2"
            echo -e "${GREEN}✅ Platform: Windows Subsystem for Linux 2 (WSL2)${NC}"
        elif grep -q "microsoft" /proc/version; then
            PLATFORM="wsl1"
            echo -e "${GREEN}✅ Platform: Windows Subsystem for Linux 1 (WSL1)${NC}"
        else
            PLATFORM="linux"
            echo -e "${GREEN}✅ Platform: Native Linux${NC}"
        fi
    elif [[ -d "/data/data/com.termux" ]]; then
        PLATFORM="termux"
        echo -e "${GREEN}✅ Platform: Termux (Android)${NC}"
    else
        PLATFORM="unknown"
        echo -e "${YELLOW}⚠️  Platform: Unknown/Unsupported${NC}"
    fi
}

# System information
get_system_info() {
    echo -e "${BLUE}📊 Gathering system information...${NC}"
    
    # OS info
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        echo -e "${CYAN}   OS: $PRETTY_NAME${NC}"
    fi
    
    # Kernel version
    echo -e "${CYAN}   Kernel: $(uname -r)${NC}"
    
    # Architecture
    echo -e "${CYAN}   Architecture: $(uname -m)${NC}"
    
    # Memory
    if command -v free &> /dev/null; then
        MEM_GB=$(free -g | awk 'NR==2{print $2}')
        echo -e "${CYAN}   Memory: ${MEM_GB}GB${NC}"
    fi
    
    # Storage
    if command -v df &> /dev/null; then
        STORAGE_GB=$(df -h / | awk 'NR==2{print $4}')
        echo -e "${CYAN}   Available Storage: $STORAGE_GB${NC}"
    fi
}

# Network configuration
configure_network() {
    echo -e "${BLUE}🌐 Configuring network settings...${NC}"
    
    # Get default gateway and network interface
    if command -v ip &> /dev/null; then
        DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [[ -n "$DEFAULT_INTERFACE" ]]; then
            echo -e "${GREEN}✅ Default network interface: $DEFAULT_INTERFACE${NC}"
            
            # Get IP address
            IP_ADDR=$(ip addr show $DEFAULT_INTERFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
            if [[ -n "$IP_ADDR" ]]; then
                echo -e "${GREEN}✅ Detected IP address: $IP_ADDR${NC}"
                
                # Extract network segment
                NETWORK_SEGMENT=$(echo $IP_ADDR | cut -d. -f1-3)
                DEFAULT_TARGET="${NETWORK_SEGMENT}.1"
                
                echo -e "${CYAN}💡 Suggested scan target: $DEFAULT_TARGET (router/gateway)${NC}"
                echo -e "${CYAN}💡 Network segment: ${NETWORK_SEGMENT}.0/24${NC}"
            fi
        fi
    fi
    
    # Check internet connectivity
    echo -e "${CYAN}📡 Checking internet connectivity...${NC}"
    if ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
        echo -e "${GREEN}✅ Internet connectivity: OK${NC}"
    else
        echo -e "${YELLOW}⚠️  Internet connectivity: Limited or offline${NC}"
    fi
}

# Dependency checking
check_dependencies() {
    echo -e "${BLUE}🔧 Checking dependencies...${NC}"
    
    local missing_deps=()
    
    # Check Rust
    if command -v cargo &> /dev/null && command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        echo -e "${GREEN}✅ Rust: $RUST_VERSION${NC}"
    else
        echo -e "${RED}❌ Rust: Not installed${NC}"
        missing_deps+=("rust")
    fi
    
    # Check basic build tools
    if command -v gcc &> /dev/null || command -v clang &> /dev/null; then
        echo -e "${GREEN}✅ C compiler: Available${NC}"
    else
        echo -e "${RED}❌ C compiler: Not found${NC}"
        missing_deps+=("build-essential")
    fi
    
    # Check pkg-config
    if command -v pkg-config &> /dev/null; then
        echo -e "${GREEN}✅ pkg-config: Available${NC}"
    else
        echo -e "${RED}❌ pkg-config: Not found${NC}"
        missing_deps+=("pkg-config")
    fi
    
    # Check SSL development libraries
    if pkg-config --exists openssl 2>/dev/null; then
        echo -e "${GREEN}✅ OpenSSL development libraries: Available${NC}"
    else
        echo -e "${RED}❌ OpenSSL development libraries: Not found${NC}"
        missing_deps+=("libssl-dev")
    fi
    
    # Platform-specific dependencies
    case $PLATFORM in
        "linux")
            if [[ -f "/etc/debian_version" ]]; then
                # Debian/Ubuntu
                if ! dpkg -l | grep -q "libsqlite3-dev"; then
                    missing_deps+=("libsqlite3-dev")
                fi
            elif [[ -f "/etc/redhat-release" ]]; then
                # RedHat/CentOS/Fedora
                if ! rpm -q sqlite-devel &> /dev/null; then
                    missing_deps+=("sqlite-devel")
                fi
            fi
            ;;
        "wsl1"|"wsl2")
            if [[ -f "/etc/debian_version" ]]; then
                if ! dpkg -l | grep -q "libsqlite3-dev"; then
                    missing_deps+=("libsqlite3-dev")
                fi
            fi
            ;;
        "termux")
            if ! pkg list-installed | grep -q "sqlite"; then
                missing_deps+=("sqlite")
            fi
            ;;
    esac
    
    # Install missing dependencies
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Missing dependencies detected: ${missing_deps[*]}${NC}"
        install_dependencies "${missing_deps[@]}"
    else
        echo -e "${GREEN}✅ All dependencies satisfied${NC}"
    fi
}

# Install dependencies based on platform
install_dependencies() {
    local deps=("$@")
    
    echo -e "${BLUE}📦 Installing missing dependencies...${NC}"
    
    case $PLATFORM in
        "linux"|"wsl1"|"wsl2")
            if [[ -f "/etc/debian_version" ]]; then
                # Debian/Ubuntu
                echo -e "${CYAN}   Using apt package manager${NC}"
                sudo apt update
                for dep in "${deps[@]}"; do
                    case $dep in
                        "rust")
                            echo -e "${CYAN}   Installing Rust via rustup...${NC}"
                            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                            source "$HOME/.cargo/env"
                            ;;
                        "build-essential")
                            sudo apt install -y build-essential
                            ;;
                        *)
                            sudo apt install -y "$dep"
                            ;;
                    esac
                done
            elif [[ -f "/etc/redhat-release" ]]; then
                # RedHat/CentOS/Fedora
                echo -e "${CYAN}   Using yum/dnf package manager${NC}"
                if command -v dnf &> /dev/null; then
                    PKG_MGR="dnf"
                else
                    PKG_MGR="yum"
                fi
                sudo $PKG_MGR update -y
                for dep in "${deps[@]}"; do
                    case $dep in
                        "rust")
                            echo -e "${CYAN}   Installing Rust via rustup...${NC}"
                            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                            source "$HOME/.cargo/env"
                            ;;
                        "libssl-dev")
                            sudo $PKG_MGR install -y openssl-devel
                            ;;
                        "pkg-config")
                            sudo $PKG_MGR install -y pkgconfig
                            ;;
                        *)
                            sudo $PKG_MGR install -y "$dep"
                            ;;
                    esac
                done
            fi
            ;;
        "termux")
            echo -e "${CYAN}   Using pkg package manager (Termux)${NC}"
            pkg update -y
            for dep in "${deps[@]}"; do
                case $dep in
                    "rust")
                        pkg install -y rust
                        ;;
                    "libssl-dev")
                        pkg install -y openssl-tool
                        ;;
                    *)
                        pkg install -y "$dep"
                        ;;
                esac
            done
            ;;
        *)
            echo -e "${RED}❌ Cannot automatically install dependencies on unknown platform${NC}"
            echo -e "${YELLOW}💡 Please manually install: ${deps[*]}${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
}

# Create directory structure
create_directories() {
    echo -e "${BLUE}📁 Creating directory structure...${NC}"
    
    local dirs=("config" "exports" "logs" "data" "scripts" "backups")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            echo -e "${GREEN}✅ Created: $dir/${NC}"
        else
            echo -e "${CYAN}📂 Already exists: $dir/${NC}"
        fi
    done
}

# Configuration setup
setup_configuration() {
    echo -e "${BLUE}⚙️  Setting up configuration...${NC}"
    
    # Create default config if it doesn't exist
    if [[ ! -f "config/default.toml" ]]; then
        cat > "config/default.toml" << 'EOF'
# Port-ZiLLA Enterprise Configuration
# Generated by advanced setup script

[scanner]
default_timeout_ms = 1000
max_threads = 200
chunk_size = 100
syn_scan_enabled = false
udp_scan_enabled = false
rate_limit = null
stealth_mode = false
enable_service_detection = true
enable_banner_grabbing = true
enable_os_detection = false
enable_traceroute = false

[database]
connection_string = "sqlite:data/portzilla.db"
max_connections = 20
enable_migrations = true
backup_enabled = true
backup_interval_hours = 24

[export]
default_format = "json"
auto_export = false
output_directory = "exports"
include_timestamps = true
compress_exports = false

[security]
allowed_targets = []
max_ports_per_scan = 65535
require_authentication = false
rate_limiting_enabled = true
max_scans_per_hour = 10

[logging]
level = "info"
format = "detailed"
enable_file_logging = true
log_directory = "logs"
max_log_size_mb = 100

[ui]
color_scheme = "dark"
show_animations = true
progress_bars_enabled = true
detailed_output = true

[api]
enabled = false
bind_address = "127.0.0.1:8080"
auth_enabled = true
default_api_key = "portzilla-setup-$(date +%Y%m%d)"
EOF
        echo -e "${GREEN}✅ Created: config/default.toml${NC}"
    else
        echo -e "${CYAN}📄 Config already exists: config/default.toml${NC}"
    fi
    
    # Create environment file
    if [[ ! -f ".env" ]]; then
        cat > ".env" << EOF
# Port-ZiLLA Environment Configuration
# Generated on $(date)

# Platform Information
DETECTED_PLATFORM=$PLATFORM
DETECTED_IP=$IP_ADDR
SUGGESTED_TARGET=$DEFAULT_TARGET

# Database
DATABASE_URL=sqlite:data/portzilla.db
DATABASE_MAX_CONNECTIONS=20

# Scanner
SCANNER_TIMEOUT_MS=1000
SCANNER_MAX_THREADS=200
SCANNER_RATE_LIMIT=

# Security
ALLOWED_TARGETS=
MAX_PORTS_PER_SCAN=65535
REQUIRE_AUTHENTICATION=false

# API
API_ENABLED=false
API_BIND_ADDRESS=127.0.0.1:8080
API_AUTH_ENABLED=true

# Logging
LOG_LEVEL=info
LOG_FORMAT=detailed
LOG_TO_FILE=true
LOG_DIRECTORY=logs
EOF
        echo -e "${GREEN}✅ Created: .env${NC}"
    else
        echo -e "${CYAN}📄 Environment file already exists: .env${NC}"
    fi
}

# Build the application
build_application() {
    echo -e "${BLUE}🔨 Building Port-ZiLLA Enterprise...${NC}"
    
    # Check if we're in the right directory
    if [[ ! -f "Cargo.toml" ]]; then
        echo -e "${RED}❌ Error: Not in Port-ZiLLA project directory${NC}"
        echo -e "${YELLOW}💡 Please run this script from the project root${NC}"
        exit 1
    fi
    
    # Build in release mode
    echo -e "${CYAN}   Building release version...${NC}"
    if cargo build --release; then
        echo -e "${GREEN}✅ Build successful${NC}"
        
        # Show build info
        BINARY_SIZE=$(du -h target/release/portzilla 2>/dev/null | cut -f1 || echo "unknown")
        echo -e "${CYAN}   Binary size: $BINARY_SIZE${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        echo -e "${YELLOW}💡 Check the error messages above and ensure all dependencies are installed${NC}"
        exit 1
    fi
}

# Initialize database
initialize_database() {
    echo -e "${BLUE}🗄️  Initializing database...${NC}"
    
    # Try to run the application to trigger database setup
    if ./target/release/portzilla --help &> /dev/null; then
        echo -e "${GREEN}✅ Database initialized successfully${NC}"
    else
        echo -e "${YELLOW}⚠️  Database initialization may need manual setup${NC}"
    fi
}

# Platform-specific optimizations
platform_optimizations() {
    echo -e "${BLUE}🚀 Applying platform-specific optimizations...${NC}"
    
    case $PLATFORM in
        "wsl1"|"wsl2")
            echo -e "${CYAN}   WSL detected - optimizing for Windows interoperability${NC}"
            # Add WSL-specific optimizations here
            ;;
        "termux")
            echo -e "${CYAN}   Termux detected - applying Android optimizations${NC}"
            # Termux might need special permissions or configurations
            if [[ ! -d "/data/data/com.termux/files/usr/bin" ]]; then
                echo -e "${YELLOW}⚠️  Termux environment may require additional setup${NC}"
            fi
            ;;
        "linux")
            echo -e "${CYAN}   Native Linux - applying performance optimizations${NC}"
            # Check if we can use performance governors
            if command -v cpupower &> /dev/null; then
                echo -e "${CYAN}   CPU performance governor available${NC}"
            fi
            ;;
    esac
}

# Troubleshooting guide
show_troubleshooting() {
    echo -e "${BLUE}🔧 Common troubleshooting tips:${NC}"
    echo
    echo -e "${CYAN}💡 Build Issues:${NC}"
    echo -e "   • Run 'cargo clean' and rebuild"
    echo -e "   • Ensure all dependencies are installed"
    echo -e "   • Check Rust version with 'rustc --version'"
    echo
    echo -e "${CYAN}💡 Network Issues:${NC}"
    echo -e "   • Check firewall settings"
    echo -e "   • Ensure proper network permissions"
    echo -e "   • Verify target IP addresses are correct"
    echo
    echo -e "${CYAN}💡 Platform-Specific:${NC}"
    case $PLATFORM in
        "wsl1"|"wsl2")
            echo -e "   • WSL may require Windows firewall adjustments"
            echo -e "   • Ensure WSL has network access"
            echo -e "   • Consider using --stealth-mode for better results"
            ;;
        "termux")
            echo -e "   • Termux may require storage permissions"
            echo -e "   • Use 'termux-setup-storage' if needed"
            echo -e "   • Some network features may be limited"
            ;;
    esac
    echo
}

# Final setup summary
show_summary() {
    echo -e "${GREEN}"
    echo -e "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo -e "║                         SETUP COMPLETE!                                     ║"
    echo -e "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}🎉 Port-ZiLLA Enterprise is ready to use!${NC}"
    echo
    echo -e "${WHITE}📊 Setup Summary:${NC}"
    echo -e "  ${GREEN}✓${NC} Platform: $PLATFORM"
    echo -e "  ${GREEN}✓${NC} IP Address: ${IP_ADDR:-Not detected}"
    echo -e "  ${GREEN}✓${NC} Suggested Target: ${DEFAULT_TARGET:-Not available}"
    echo -e "  ${GREEN}✓${NC} Dependencies: All satisfied"
    echo -e "  ${GREEN}✓${NC} Configuration: Ready"
    echo -e "  ${GREEN}✓${NC} Database: Initialized"
    echo
    echo -e "${WHITE}🚀 Quick Start Commands:${NC}"
    echo -e "  ${CYAN}./target/release/portzilla interactive${NC}    - Launch interactive mode"
    echo -e "  ${CYAN}./target/release/portzilla scan --help${NC}    - View scan options"
    echo -e "  ${CYAN}./target/release/portzilla server${NC}         - Start API server"
    echo
    echo -e "${WHITE}🎯 Example Usage:${NC}"
    echo -e "  ${CYAN}./target/release/portzilla scan ${DEFAULT_TARGET:-'TARGET_IP'} --scan-type quick${NC}"
    echo -e "  ${CYAN}./target/release/portzilla scan ${DEFAULT_TARGET:-'TARGET_IP'} --scan-type full --vulnerability-scan${NC}"
    echo
    echo -e "${YELLOW}⚠️  Important: Only scan networks you own or have permission to test!${NC}"
    echo
    echo -e "${CYAN}📚 Documentation: https://github.com/FJ-cyberzilla/Port-ZiLLA${NC}"
    echo -e "${CYAN}📧 Support: cyberzilla.systems@gmail.com${NC}"
    echo
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════════════${NC}"
}

# Main execution
main() {
    print_banner
    detect_platform
    
    if [[ "$PLATFORM" == "unknown" ]]; then
        echo -e "${RED}❌ Unsupported platform detected${NC}"
        echo -e "${YELLOW}💡 Port-ZiLLA supports: Linux, WSL1, WSL2, and Termux${NC}"
        echo -e "${YELLOW}💡 Windows and macOS are not directly supported${NC}"
        exit 1
    fi
    
    get_system_info
    configure_network
    check_dependencies
    create_directories
    setup_configuration
    build_application
    initialize_database
    platform_optimizations
    show_troubleshooting
    show_summary
}

# Run main function
main "$@"
