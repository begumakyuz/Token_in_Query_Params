use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// [L14-Auditor] v2.1 Professional Forensic Scanner
/// Purpose: Identify unmasked sensitive credentials in server logs.
#[derive(Debug, Default)]
struct AuditSummary {
    processed_lines: usize,
    token_leaks: usize,
    credential_leaks: usize,
    key_vulnerabilities: usize,
    execution_time: Option<Duration>,
}

fn main() {
    let timer = Instant::now();
    println!("🛡️  [L14-Auditor] Initializing High-Performance Forensic Scan...");

    // Target log detection (Default to standard forensic path)
    let log_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "forensics/access.log".to_string());

    if !Path::new(&log_path).exists() {
        eprintln!("❌ [FATAL] Forensic data source missing: {}. Audit terminated.", log_path);
        std::process::exit(1);
    }

    let mut summary = AuditSummary::default();

    match scan_log_file(&log_path, &mut summary) {
        Ok(audit_content) => {
            summary.execution_time = Some(timer.elapsed());
            display_audit_results(&summary);
            
            if let Err(e) = generate_forensic_report(&log_path, audit_content) {
                eprintln!("⚠️  [WARNING] Forensic report generation failed: {}", e);
            }
        }
        Err(e) => {
            eprintln!("❌ [RUNTIME_ERROR] Security scan failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Scans the log file and populates the audit summary.
fn scan_log_file(path: &str, summary: &mut AuditSummary) -> io::Result<String> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut report = String::from("# 📑 Forensic Security Audit Report\n\n");

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        summary.processed_lines += 1;

        if let Some(risk_type) = evaluate_line_risk(&line) {
            let alert = format!(
                "🚨 [ALERT] {} detected at line {}: {}",
                risk_type, line_num + 1, line
            );
            println!("{}", alert);
            report.push_str(&format!("* {}\n", alert));

            match risk_type.as_str() {
                "TOKEN_LEAK" => summary.token_leaks += 1,
                "PASSWORD_EXPOSURE" => summary.credential_leaks += 1,
                "PRIVATE_KEY_LEAK" => summary.key_vulnerabilities += 1,
                _ => (),
            }
        }
    }

    Ok(report)
}

/// Core logic for identifying sensitive data patterns.
fn evaluate_line_risk(content: &str) -> Option<String> {
    let lower = content.to_lowercase();
    
    // Pattern 1: Unmasked Token in URI
    if content.contains("token=") && !content.contains("token=***") {
        return Some("TOKEN_LEAK".to_string());
    }
    
    // Pattern 2: Credentials in body/parameter
    if (lower.contains("password=") || lower.contains("passwd=")) && !content.contains("=***") {
        return Some("PASSWORD_EXPOSURE".to_string());
    }

    // Pattern 3: Private Key exposure
    if content.contains("BEGIN PRIVATE KEY") || content.contains("ssh-rsa") {
        return Some("PRIVATE_KEY_LEAK".to_string());
    }

    None
}

/// Prints a professional summary of the audit.
fn display_audit_results(summary: &AuditSummary) {
    println!("\n==================================================");
    println!("📊 FORENSIC AUDIT SUMMARY");
    println!("--------------------------------------------------");
    println!("  Logs Processed   : {}", summary.processed_lines);
    println!("  Token Leaks      : {}", summary.token_leaks);
    println!("  Credentials Found: {}", summary.credential_leaks);
    println!("  Key Exposures    : {}", summary.key_vulnerabilities);
    println!("  Engine Latency   : {:?}", summary.execution_time.unwrap_or_default());
    println!("==================================================");

    let total_risks = summary.token_leaks + summary.credential_leaks + summary.key_vulnerabilities;
    if total_risks > 0 {
        println!("☣️  [SYSTEM_STATUS: COMPROMISED] Critical vulnerabilities detected.");
    } else {
        println!("✅ [SYSTEM_STATUS: CLEAN] No sensitive data patterns identified.");
    }
}

/// Saves the audit report to a local markdown file.
fn generate_forensic_report(log_path: &str, content: String) -> io::Result<()> {
    let target = format!("{}.audit.md", log_path);
    let mut file = fs::File::create(&target)?;
    write!(file, "{}", content)?;
    println!("📈 [GENERATE] Forensic report successfully saved to: {}", target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_token_detection() {
        assert!(evaluate_line_risk("GET /?token=xyz").is_some());
        assert!(evaluate_line_risk("GET /?token=***").is_none());
    }

    #[test]
    fn verify_credential_detection() {
        assert!(evaluate_line_risk("POST /login?password=admin").is_some());
    }

    #[test]
    fn verify_key_detection() {
        assert!(evaluate_line_risk("ssh-rsa AAAAB3...").is_some());
    }
}
