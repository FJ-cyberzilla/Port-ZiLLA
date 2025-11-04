use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{info, warn, error};

pub struct RateLimiter {
    requests: RwLock<HashMap<String, Vec<Instant>>>,
    window: Duration,
    max_requests: u32,
}

impl RateLimiter {
    pub fn new(window: Duration, max_requests: u32) -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            window,
            max_requests,
        }
    }

    pub fn check_rate_limit(&self, identifier: &str) -> Result<()> {
        let now = Instant::now();
        let window_start = now - self.window;

        let mut requests = self.requests.write()
            .map_err(|_| Error::RateLimit("Failed to access rate limiter".to_string()))?;

        let requests_for_id = requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        
        // Clean up old requests outside the window
        requests_for_id.retain(|&time| time >= window_start);
        
        if requests_for_id.len() >= self.max_requests as usize {
            return Err(Error::RateLimit(format!(
                "Rate limit exceeded: {} requests in {:?}",
                self.max_requests, self.window
            )));
        }

        requests_for_id.push(now);
        Ok(())
    }

    pub fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let window_start = now - self.window;

        if let Ok(mut requests) = self.requests.write() {
            requests.retain(|_, timestamps| {
                timestamps.retain(|&time| time >= window_start);
                !timestamps.is_empty()
            });
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default: 100 requests per minute per IP/API key
        Self::new(Duration::from_secs(60), 100)
    }
}

pub struct RequestLogger;

impl RequestLogger {
    pub fn log_request(&self, method: &str, path: &str, status_code: u16, duration: Duration, client_ip: &str) {
        let status_color = match status_code {
            200..=299 => "32", // Green
            300..=399 => "33", // Yellow
            400..=499 => "31", // Red
            500..=599 => "35", // Magenta
            _ => "37",         // White
        };

        info!(
            "{} {} {} {} {}ms",
            client_ip,
            method,
            path,
            format!("\x1b[{}m{}\x1b[0m", status_color, status_code),
            duration.as_millis()
        );
    }

    pub fn log_error(&self, error: &Error, context: &str) {
        error!("API Error [{}]: {}", context, error);
    }

    pub fn log_security_event(&self, event: &str, client_ip: &str, details: &str) {
        warn!("SECURITY EVENT - {} from {}: {}", event, client_ip, details);
    }
}

impl Default for RequestLogger {
    fn default() -> Self {
        Self
    }
}
