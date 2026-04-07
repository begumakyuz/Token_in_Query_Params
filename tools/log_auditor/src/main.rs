use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 🚀 [L14-Auditor] v4.0 Elite Forensic Engine (Parallel CSV Edition)
/// Purpose: High-performance, multi-threaded log auditing with structured CSV evidence.
#[derive(Debug, Default, Clone)]
struct AuditSummary {
    processed_lines: usize,
    token_leaks: usize,
    credential_leaks: usize,
    key_vulnerabilities: usize,
    violations: Vec<LogViolation>,
}

#[derive(Debug, Clone)]
struct LogViolation {
    line: usize,
    risk: String,
    content: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        display_help();
        return;
    }

    let timer = Instant::now();
    println!("\x1b[1;36m🛡️  [L14-Auditor] Initializing ELITE Parallel Forensic Scan (v4.0)...\x1b[0m");

    let log_path = args.get(1).cloned().unwrap_or_else(|| "forensics/access.log".to_string());
    if !Path::new(&log_path).exists() {
        eprintln!("\x1b[1;31m❌ [FATAL] Forensic data source missing: {}. Audit terminated.\x1b[0m", log_path);
        std::process::exit(1);
    }

    let num_threads = 4;
    let summary = Arc::new(Mutex::new(AuditSummary::default()));
    let mut handles = vec![];

    println!("\x1b[0;33m⚙️  Allocating {} worker threads for parallel forensic scan...\x1b[0m", num_threads);

    for i in 0..num_threads {
        let summary_ref = Arc::clone(&summary);
        let log_path_clone = log_path.clone();

        let handle = thread::spawn(move || {
            if let Ok(file) = File::open(&log_path_clone) {
                let reader = io::BufReader::new(file);
                for (num, line_result) in reader.lines().enumerate() {
                    if num % num_threads == i {
                        if let Ok(line) = line_result {
                            if let Some(risk) = evaluate_line_risk(&line) {
                                let mut s = summary_ref.lock().unwrap();
                                s.processed_lines += 1;
                                s.violations.push(LogViolation {
                                    line: num + 1,
                                    risk: risk.clone(),
                                    content: line.clone(),
                                });
                                match risk.as_str() {
                                    "TOKEN_LEAK" => s.token_leaks += 1,
                                    "PASSWORD_EXPOSURE" => s.credential_leaks += 1,
                                    "PRIVATE_KEY_LEAK" => s.key_vulnerabilities += 1,
                                    _ => (),
                                }
                            }
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles { handle.join().unwrap(); }

    let final_summary = summary.lock().unwrap().clone();
    let elapsed = timer.elapsed();

    display_audit_results(&final_summary, elapsed);

    // Final Multi-format Reporting (MD & CSV)
    let _ = generate_forensic_report(&log_path, &final_summary);
    let _ = export_results_to_csv(&log_path, &final_summary);
}

fn display_help() {
    println!("\x1b[1;34m==================================================");
    println!("📖 L14-AUDITOR v4.0 (PARALLEL CSV) HELP MENU");
    println!("==================================================");
    println!("Usage: auditor <log_file_path>");
    println!("\nFeatures:");
    println!("  --help        Display technical guide");
    println!("  Parallelism   4x Threads concurrency scanning");
    println!("  Reports       Auto-Generates MD and CSV evidence");
    println!("  Forensics     Token, Password, and SSH Pattern Auth\x1b[0m");
}

fn evaluate_line_risk(content: &str) -> Option<String> {
    let lower = content.to_lowercase();
    if content.contains("token=") && !content.contains("token=***") { return Some("TOKEN_LEAK".to_string()); }
    if (lower.contains("password=") || lower.contains("passwd=")) && !content.contains("=***") { return Some("PASSWORD_EXPOSURE".to_string()); }
    if content.contains("BEGIN PRIVATE KEY") || content.contains("ssh-rsa") { return Some("PRIVATE_KEY_LEAK".to_string()); }
    None
}

fn display_audit_results(summary: &AuditSummary, elapsed: Duration) {
    println!("\n\x1b[1;35m==================================================");
    println!("📊 ELITE FORENSIC AUDIT SUMMARY (v4.0)");
    println!("--------------------------------------------------");
    println!("  Concurreny Units : 4 Active Threads");
    println!("  Total Processed  : {}", summary.processed_lines);
    println!("  Scan Efficiency  : {:?} (Hardened Optimization)", elapsed);
    println!("==================================================\x1b[0m");
}

fn generate_forensic_report(log_path: &str, summary: &AuditSummary) -> io::Result<()> {
    let target = format!("{}.audit.md", log_path);
    let mut file = fs::File::create(&target)?;
    write!(file, "# 📑 Elite Forensic Security Audit\n\n- **Status:** FINISHED\n- **Token Leaks:** {}\n- **Credential Leaks:** {}\n", summary.token_leaks, summary.credential_leaks)?;
    println!("\x1b[0;32m📈 [GENERATE] Summary saved to: {}\x1b[0m", target);
    Ok(())
}

fn export_results_to_csv(log_path: &str, summary: &AuditSummary) -> io::Result<()> {
    let target = format!("{}.evidence.csv", log_path);
    let mut file = fs::File::create(&target)?;
    writeln!(file, "Line,Risk_Type,Raw_Content")?;
    for v in &summary.violations {
        writeln!(file, "{},{},\"{}\"", v.line, v.risk, v.content.replace("\"", "'"))?;
    }
    println!("\x1b[0;32m📊 [CSV_EXPORT] Forensic evidence exported to: {}\x1b[0m", target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verify_detection() { assert!(evaluate_line_risk("token=ABC").is_some()); }
}
