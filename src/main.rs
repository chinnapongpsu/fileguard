mod filetype;
mod pdf_analysis;

use pdf_analysis::analyze_file;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;
// use filetype::FileType;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Existing code for file/directory handling
    if args.len() == 2 {
        let input_path = &args[1];
        let path = Path::new(input_path);

        if path.is_file() {
            scan_and_report(input_path);
        } else if path.is_dir() {
            visit_dir(path);
        } else {
            eprintln!("Provided path is neither a file nor a directory.");
            std::process::exit(1);
        }
    } else if args.len() >= 3 && args[1] == "--bytes" {
        // Add support for analyzing raw bytes from a file
        let file_path = &args[2];
        match fs::read(file_path) {
            Ok(bytes) => {
                scan_from_bytes(&bytes, &format!("bytes from {}", file_path));
            }
            Err(e) => {
                eprintln!("Failed to read file bytes: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Usage: {} <file_or_directory_path>", args[0]);
        eprintln!("   or: {} --bytes <file_path>", args[0]);
        std::process::exit(1);
    }
}

fn visit_dir(dir: &Path) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Failed to read directory: {}", e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_dir(&path);
        } else if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            if ["pdf", "docx", "jpg", "jpeg", "png"].contains(&ext.as_str()) {
                scan_and_report(&path.to_string_lossy());
            }
        }
    }
}

fn scan_and_report(file_path: &str) {
    println!("🔍 Analyzing file: {}", file_path);

    let start = Instant::now();
    analyze_file(file_path);
    let duration = start.elapsed();

    println!(
        "⏱️  Execution time: {:.6} seconds\n",
        duration.as_secs_f64()
    );
}

// New function to scan from a byte stream
fn scan_from_bytes(data: &[u8], source_name: &str) {
    println!("🔍 Analyzing data from: {}", source_name);

    let start = Instant::now();
    let (file_type, result) = pdf_analysis::analyze_data(data);

    println!("Detected file type: {:?}", file_type);

    match result {
        pdf_analysis::AnalysisResult::Clean => println!("{:?} Analysis: Clean", file_type),
        pdf_analysis::AnalysisResult::Suspicious(findings) => {
            println!("{:?} Analysis: Suspicious", file_type);
            for finding in findings {
                println!("- {}", finding);
            }
        }
    }

    let duration = start.elapsed();
    println!(
        "⏱️  Execution time: {:.6} seconds\n",
        duration.as_secs_f64()
    );
}
