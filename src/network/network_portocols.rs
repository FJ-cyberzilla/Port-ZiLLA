use crate::error::Result;
use std::collections::HashMap;

/// Common network protocol definitions and utilities
pub struct ProtocolUtils;

impl ProtocolUtils {
    pub fn get_common_ports() -> HashMap<u16, &'static str> {
        let mut ports = HashMap::new();
        
        // Well-known ports
        ports.insert(21, "FTP");
        ports.insert(22, "SSH");
        ports.insert(23, "Telnet");
        ports.insert(25, "SMTP");
        ports.insert(53, "DNS");
        ports.insert(80, "HTTP");
        ports.insert(110, "POP3");
        ports.insert(143, "IMAP");
        ports.insert(443, "HTTPS");
        ports.insert(993, "IMAPS");
        ports.insert(995, "POP3S");
        
        // Database ports
        ports.insert(1433, "MSSQL");
        ports.insert(3306, "MySQL");
        ports.insert(5432, "PostgreSQL");
        ports.insert(27017, "MongoDB");
        ports.insert(6379, "Redis");
        
        // Remote access
        ports.insert(3389, "RDP");
        ports.insert(5900, "VNC");
        
        // File sharing
        ports.insert(139, "NetBIOS");
        ports.insert(445, "SMB");
        
        // Other common services
        ports.insert(111, "RPC");
        ports.insert(135, "MSRPC");
        ports.insert(161, "SNMP");
        ports.insert(389, "LDAP");
        ports.insert(636, "LDAPS");
        ports.insert(993, "IMAPS");
        ports.insert(995, "POP3S");
        ports.insert(1723, "PPTP");
        ports.insert(8080, "HTTP-Alt");
        ports.insert(8443, "HTTPS-Alt");
        
        ports
    }

    pub fn get_port_description(port: u16) -> Option<&'static str> {
        Self::get_common_ports().get(&port).copied()
    }

    pub fn is_common_port(port: u16) -> bool {
        Self::get_common_ports().contains_key(&port)
    }

    pub fn get_service_ports(service: &str) -> Vec<u16> {
        let common_ports = Self::get_common_ports();
        common_ports
            .iter()
            .filter_map(|(&port, &name)| {
                if name.to_lowercase().contains(&service.to_lowercase()) {
                    Some(port)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Protocol-specific constants and utilities
pub mod constants {
    // TCP flags
    pub const TCP_FIN: u8 = 0x01;
    pub const TCP_SYN: u8 = 0x02;
    pub const TCP_RST: u8 = 0x04;
    pub const TCP_PSH: u8 = 0x08;
    pub const TCP_ACK: u8 = 0x10;
    pub const TCP_URG: u8 = 0x20;

    // Common protocol timeouts
    pub const DEFAULT_TCP_TIMEOUT_MS: u64 = 1000;
    pub const DEFAULT_UDP_TIMEOUT_MS: u64 = 2000;
    pub const DEFAULT_BANNER_TIMEOUT_MS: u64 = 5000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_ports() {
        let ports = ProtocolUtils::get_common_ports();
        assert!(ports.contains_key(&80)); // HTTP
        assert!(ports.contains_key(&443)); // HTTPS
        assert!(ports.contains_key(&22)); // SSH
    }

    #[test]
    fn test_port_description() {
        assert_eq!(ProtocolUtils::get_port_description(80), Some("HTTP"));
        assert_eq!(ProtocolUtils::get_port_description(9999), None);
    }

    #[test]
    fn test_service_ports() {
        let web_ports = ProtocolUtils::get_service_ports("HTTP");
        assert!(web_ports.contains(&80));
        assert!(web_ports.contains(&8080));
    }
              }
