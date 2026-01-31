// @id: port-scanner-async
// @name: High-Speed Async TCP Port Scanner
// @author: CERT-X-GEN Security Team
// @severity: info
// @description: Ultra-fast concurrent port scanning using Rust async runtime
// @tags: recon, port-scan, rust, performance, async
// @cwe: N/A
// @cvss: N/A
// @references: https://docs.rs/tokio
// @confidence: 95
// @version: 1.0.0
//
// WHY RUST?
// Port scanning requires:
// - Thousands of concurrent connections
// - Minimal memory per connection
// - Fast timeout handling
// - Zero runtime overhead
//
// Rust provides:
// - async/await with zero-cost abstractions
// - Memory safety without garbage collection
// - Tokio runtime for high-performance async I/O
// - Compile-time guarantees

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// For standalone execution without tokio, we use blocking I/O
// In production, this would use tokio for true async
use std::net::TcpStream;
use std::thread;
use std::sync::mpsc;

const DEFAULT_TIMEOUT_MS: u64 = 500;
const DEFAULT_THREADS: usize = 100;

#[derive(Debug, Clone)]
struct ScanResult {
    port: u16,
    open: bool,
    banner: Option<String>,
}

#[derive(Debug)]
struct ScanReport {
    host: String,
    open_ports: Vec<u16>,
    ports_scanned: usize,
    duration_ms: u64,
}

/// Scan a single port with timeout
fn scan_port(host: &str, port: u16, timeout_ms: u64) -> ScanResult {
    let addr = format!("{}:{}", host, port);
    
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(socket_addr) = addrs.next() {
                match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
                    Ok(stream) => {
                        // Port is open - try to grab banner
                        let banner = grab_banner(&stream, timeout_ms);
                        ScanResult { port, open: true, banner }
                    }
                    Err(_) => ScanResult { port, open: false, banner: None }
                }
            } else {
                ScanResult { port, open: false, banner: None }
            }
        }
        Err(_) => ScanResult { port, open: false, banner: None }
    }
}

/// Attempt to grab service banner
fn grab_banner(stream: &TcpStream, _timeout_ms: u64) -> Option<String> {
    use std::io::{Read, Write};
    
    // Set read timeout
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    
    // Try to read initial banner (some services send data immediately)
    let mut buffer = [0u8; 256];
    let mut stream_clone = stream.try_clone().ok()?;
    
    match stream_clone.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            let cleaned: String = banner
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(100)
                .collect();
            if !cleaned.trim().is_empty() {
                return Some(cleaned.trim().to_string());
            }
        }
        _ => {}
    }
    
    // Try sending HTTP probe
    let _ = stream_clone.write_all(b"GET / HTTP/1.0\r\n\r\n");
    
    match stream_clone.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            if response.contains("HTTP") {
                return Some("HTTP".to_string());
            }
        }
        _ => {}
    }
    
    None
}

/// Parallel port scanner using thread pool
fn parallel_scan(host: &str, ports: Vec<u16>, timeout_ms: u64, num_threads: usize) -> Vec<ScanResult> {
    let (tx, rx) = mpsc::channel();
    let host = Arc::new(host.to_string());
    let ports_arc = Arc::new(ports);
    let port_idx = Arc::new(AtomicUsize::new(0));
    
    let mut handles = Vec::new();
    
    for _ in 0..num_threads {
        let tx = tx.clone();
        let host = Arc::clone(&host);
        let ports = Arc::clone(&ports_arc);
        let idx = Arc::clone(&port_idx);
        
        let handle = thread::spawn(move || {
            loop {
                let i = idx.fetch_add(1, Ordering::SeqCst);
                if i >= ports.len() {
                    break;
                }
                
                let port = ports[i];
                let result = scan_port(&host, port, timeout_ms);
                
                if result.open {
                    let _ = tx.send(result);
                }
            }
        });
        
        handles.push(handle);
    }
    
    // Drop original sender
    drop(tx);
    
    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }
    
    // Collect results
    rx.iter().collect()
}

/// Parse port range string (e.g., "1-1024" or "80,443,8080")
fn parse_ports(port_spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for part in port_spec.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    
    ports
}

/// Output results as JSON
fn output_json(report: &ScanReport, results: &[ScanResult]) {
    println!("{{\"findings\":[{{");
    println!("  \"id\":\"port-scan-results\",");
    println!("  \"name\":\"Port Scan Results\",");
    println!("  \"severity\":\"info\",");
    println!("  \"confidence\":95,");
    println!("  \"description\":\"Scanned {} ports on {} in {}ms. Found {} open ports.\",",
             report.ports_scanned, report.host, report.duration_ms, report.open_ports.len());
    println!("  \"evidence\":{{");
    println!("    \"host\":\"{}\",", report.host);
    println!("    \"ports_scanned\":{},", report.ports_scanned);
    println!("    \"duration_ms\":{},", report.duration_ms);
    println!("    \"open_ports\":[{}],", 
             report.open_ports.iter()
                   .map(|p| p.to_string())
                   .collect::<Vec<_>>()
                   .join(","));
    
    // Include services detected
    println!("    \"services\":[");
    for (i, result) in results.iter().enumerate() {
        let banner = result.banner.as_deref().unwrap_or("");
        let comma = if i < results.len() - 1 { "," } else { "" };
        println!("      {{\"port\":{},\"banner\":\"{}\"}}{}", result.port, banner, comma);
    }
    println!("    ]");
    println!("  }}");
    println!("}}]}}")
}

fn main() {
    // Get configuration from environment or args
    let host = env::var("CERT_X_GEN_TARGET_HOST")
        .or_else(|_| env::args().nth(1).ok_or(()))
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    
    let port_spec = env::var("CERT_X_GEN_PORT_RANGE")
        .or_else(|_| env::args().nth(2).ok_or(()))
        .unwrap_or_else(|_| "1-1024".to_string());
    
    let timeout_ms: u64 = env::var("CERT_X_GEN_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    
    let num_threads: usize = env::var("CERT_X_GEN_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_THREADS);
    
    // Parse ports
    let ports = parse_ports(&port_spec);
    let ports_count = ports.len();
    
    // Start scan
    let start = std::time::Instant::now();
    let results = parallel_scan(&host, ports, timeout_ms, num_threads);
    let duration = start.elapsed();
    
    // Build report
    let open_ports: Vec<u16> = results.iter().map(|r| r.port).collect();
    
    let report = ScanReport {
        host: host.clone(),
        open_ports: open_ports.clone(),
        ports_scanned: ports_count,
        duration_ms: duration.as_millis() as u64,
    };
    
    // Output JSON
    output_json(&report, &results);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("1-10");
        assert_eq!(ports.len(), 10);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[9], 10);
    }
    
    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports("80,443,8080");
        assert_eq!(ports, vec![80, 443, 8080]);
    }
    
    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80-82,443");
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }
}
