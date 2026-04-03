use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn main() {
    println!("🔐 [Rust Token Auditor] Starting Forensic Log Analysis...");

    // Hedef log dosyasını bul (Projeye göre forensic klasöründeki access.log)
    let log_path = env::args().nth(1).unwrap_or_else(|| "../../forensics/access.log".to_string());
    
    // Güvenli hata yönetimi ile dosyayı aç
    if let Ok(lines) = read_lines(&log_path) {
        let mut leak_count = 0;
        let mut total_lines = 0;

        for (index, line) in lines.enumerate() {
            if let Ok(content) = line {
                total_lines += 1;
                
                // Zafiyet Tespiti: token=x var mı ve *** ile MASKELENMEMİŞ mi?
                if content.contains("token=") && !content.contains("token=***") {
                    println!("🚨 [CRITICAL ALERT] Token Leak Detected at Line {}!", index + 1);
                    println!("   -> Log Entry: {}", content);
                    leak_count += 1;
                }
            }
        }

        println!("--------------------------------------------------");
        println!("📊 [Audit Summary]");
        println!("   Total Logs Scanned : {}", total_lines);
        println!("   Total Leaks Found  : {}", leak_count);

        if leak_count > 0 {
            println!("❌ [FAIL] Immediate incident response required. Unmasked tokens found.");
        } else {
            println!("✅ [PASS] No unmasked tokens found. Logs are clean.");
        }
    } else {
        eprintln!("❌ [ERROR] Could not read log file: {}. Make sure the path is correct.", log_path);
    }
}

// Memory-safe line reader (tüm dosyayı belleğe almaz)
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
