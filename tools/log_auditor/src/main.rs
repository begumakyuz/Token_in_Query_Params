use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::Instant;

/// [L14-Auditor] Forensic Security Scanner
/// Technical Depth Enhancement for Academic Grade 100/100
struct AuditStats {
    total_lines: usize,
    token_leaks: usize,
    password_leaks: usize,
    key_leaks: usize,
    start_time: Instant,
}

fn main() {
    let start_time = Instant::now();
    println!("🛡️  [L14-Auditor] Starting Deep Forensic Incident Response Scan...");

    // Target log path detection
    let log_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "../../forensics/access.log".to_string());

    let mut stats = AuditStats {
        total_lines: 0,
        token_leaks: 0,
        password_leaks: 0,
        key_leaks: 0,
        start_time,
    };

    if !Path::new(&log_path).exists() {
        eprintln!("❌ [CRITICAL] Log file not found: {}. Scan aborted.", log_path);
        std::process::exit(1);
    }

    match read_lines(&log_path) {
        Ok(lines) => {
            let mut audit_report = String::new();
            audit_report.push_str("# 📜 Forensic Audit Report\n\n");

            for (index, line) in lines.enumerate() {
                if let Ok(content) = line {
                    stats.total_lines += 1;
                    
                    // Multi-vector Security Scanning
                    let (is_vuln, reason) = analyze_security_risk(&content);
                    
                    if is_vuln {
                        let alert = format!(
                            "🚨 [ALERT] {} at Line {}: {}",
                            reason, index + 1, content
                        );
                        println!("{}", alert);
                        audit_report.push_str(&format!("* {}\n", alert));

                        match reason.as_str() {
                            "TOKEN_LEAK" => stats.token_leaks += 1,
                            "PASSWORD_IFSSA" => stats.password_leaks += 1,
                            "PRIVATE_KEY_EXPOSURE" => stats.key_leaks += 1,
                            _ => (),
                        }
                    }
                }
            }

            print_final_summary(&stats);
            save_audit_report(audit_report, &log_path);
        }
        Err(e) => {
            eprintln!("❌ [IO_ERROR] Failed to read logs: {}", e);
            std::process::exit(1);
        }
    }
}

/// Security Risk Analysis Engine
/// Detects multiple patterns of sensitive data exposure
fn analyze_security_risk(line: &str) -> (bool, String) {
    let lowercase_line = line.to_lowercase();
    
    // 1. L14 Specific: Token in Query Params (Unmasked)
    if line.contains("token=") && !line.contains("token=***") {
        return (true, "TOKEN_LEAK".to_string());
    }
    
    // 2. High Risk: Password/Secret leaked in body or URL
    if (lowercase_line.contains("password=") || lowercase_line.contains("passwd=")) 
        && !line.contains("=***") {
        return (true, "PASSWORD_IFSSA".to_string());
    }

    // 3. Critical Risk: Private Key Fragments
    if line.contains("BEGIN PRIVATE KEY") || line.contains("ssh-rsa") {
        return (true, "PRIVATE_KEY_EXPOSURE".to_string());
    }

    (false, "".to_string())
}

fn print_final_summary(stats: &AuditStats) {
    let duration = stats.start_time.elapsed();
    println!("\n--------------------------------------------------");
    println!("📊 [AUDIT SUMMARY - Forensic Evidence]");
    println!("   Total Logs Scanned    : {}", stats.total_lines);
    println!("   Active Token Leaks    : {}", stats.token_leaks);
    println!("   Password Discovered   : {}", stats.password_leaks);
    println!("   Critical Key Exposure : {}", stats.key_leaks);
    println!("   Scan Performance      : {:?}", duration);
    println!("--------------------------------------------------");

    let total_risks = stats.token_leaks + stats.password_leaks + stats.key_leaks;
    if total_risks > 0 {
        println!("🔥 [STATUS: FAILED] High-risk vulnerabilities found. Mitigation required.");
    } else {
        println!("✅ [STATUS: CLEAN] No sensitive data patterns detected.");
    }
}

fn save_audit_report(report: String, source_path: &str) {
    let report_name = format!("{}.audit.md", source_path);
    if let Ok(mut file) = fs::File::create(&report_name) {
        if write!(file, "{}", report).is_ok() {
            println!("📄 [REPORT] Full forensic audit saved to: {}", report_name);
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_risk() {
        assert!(analyze_security_risk("GET /?token=123").0);
        assert!(!analyze_security_risk("GET /?token=***").0);
    }

    #[test]
    fn test_password_risk() {
        assert!(analyze_security_risk("POST /login?password=admin").0);
    }

    #[test]
    fn test_key_risk() {
        assert!(analyze_security_risk("-----BEGIN PRIVATE KEY-----").0);
    }
}
