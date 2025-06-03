use std::fs::File;
use std::io::Read;
use std::process;
use regex::Regex;
use zip::ZipArchive;
use std::io::Cursor;


use crate::filetype::{detect_file_type, FileType};


use once_cell::sync::Lazy;


// Precompiled regex definitions
static JS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/\s*/javascript\s+/js").unwrap());
static LAUNCH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/\s*/launch\s+/f\s+\(([^)]+)\)").unwrap());
static OPENACTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/openaction\s+<<[^>]*(/js|/launch)[^>]*>>").unwrap());
static UNC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\\\\[a-z0-9][a-z0-9_.-]{1,98}[a-z0-9]\\[^\s\\/:*?"<>|]{2,}"#).unwrap());
static URI_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"/\s*/uri\s*/uri\s*\(([^)]+)\)"#).unwrap());
const EICAR_SIGNATURE: &[u8] = b"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*";



use std::time::Instant;

fn timed_step<F, T>(label: &str, mut f: F) -> T
where
    F: FnMut() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    println!("⏱️  Step '{}' took {:.6} seconds", label, duration.as_secs_f64());
    result
}


#[derive(Debug)]
pub enum PdfThreatLevel {
    Clean,
    Suspicious(Vec<String>),
}

#[derive(Debug)]
pub enum AnalysisResult {
  Clean,
  Suspicious(Vec<String>),
}

const ENTROPY_SUSPICIOUS_THRESHOLD: f64 = 7.9;

const RISK_THRESHOLD: u32 = 10;
const IMAGE_ENTROPY_THRESHOLD: f64 = 7.9;
const DOCX_SUSPICIOUS_KEYWORDS: [&str; 6] = [
    "powershell", "cmd.exe", "wscript", "mimikatz", "dropper", ".ps1",
];


pub fn analyze_file(file_path: &str) {
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            process::exit(1);
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        process::exit(1);
    }

    let file_type = detect_file_type(&buffer);
    println!("Detected file type: {:?}", file_type);

    match file_type {
        FileType::Pdf => match analyze_pdf(&buffer) {
            PdfThreatLevel::Clean => println!("PDF Analysis: Clean"),
            PdfThreatLevel::Suspicious(f) => {
                println!("PDF Analysis: Suspicious");
                for ff in f {
                    println!("- {}", ff);
                }
            }
        },
        FileType::Docx => {
            let findings = analyze_docx(&buffer);
            if !findings.is_empty() {
                println!("DOCX Analysis: Suspicious");
                for f in findings {
                    println!("- {}", f);
                }
            } else {
                println!("DOCX Analysis: Clean");
            }
        }
        FileType::Png => {
            let findings = analyze_png(&buffer);
            if !findings.is_empty() {
                println!("PNG Analysis: Suspicious");
                for f in findings {
                    println!("- {}", f);
                }
            } else {
                println!("PNG Analysis: Clean");
            }
        }
        FileType::Jpg => {
            let findings = analyze_jpg(&buffer);
            if !findings.is_empty() {
                println!("JPG Analysis: Suspicious");
                for f in findings {
                    println!("- {}", f);
                }
            } else {
                println!("JPG Analysis: Clean");
            }
        }
        _ => println!("Unsupported or unknown file type."),
    }
    
}


fn analyze_pdf(data: &[u8]) -> PdfThreatLevel {
    let content = String::from_utf8_lossy(data).to_lowercase();
    let mut findings = Vec::new();
    let mut score = 0;

    if timed_step("Check JS regex", || JS_REGEX.is_match(&content)) {
        findings.push("Embedded JavaScript action detected".to_string());
        score += 8;
    }

    timed_step("Check Launch regex", || {
        for cap in LAUNCH_REGEX.captures_iter(&content) {
            let target = &cap[1].to_lowercase(); // Apply lowercase *here* only if needed
            findings.push(format!("Launch action to '{}'", target));
            score += if target.contains(".exe") || target.contains("cmd.exe") { 10 } else { 5 };
        }
    });

    // Other unchanged steps...
    // Replace content.matches(" obj").count() with:
    timed_step("Object count heuristic", || {
        let obj_count = content.as_bytes()
            .windows(4)
            .filter(|w| *w == b" obj")
            .count();
        if obj_count > 3000 {
            findings.push(format!("High object count: {}", obj_count));
            score += 3;
        }
    });

    // Optional: use Rayon or parallel iterator for large `captures_iter`, but test first.
    // Use case-insensitive regex to avoid pre-lowercasing whole content.

    if score >= RISK_THRESHOLD {
        findings.push(format!("⚠️ Risk score = {} (threshold = {})", score, RISK_THRESHOLD));
        PdfThreatLevel::Suspicious(findings)
    } else {
        PdfThreatLevel::Clean
    }
}



/// Calculate Shannon entropy of byte slice
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}


fn analyze_docx(data: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    let cursor = Cursor::new(data);
    if let Ok(mut archive) = ZipArchive::new(cursor) {
        for i in 0..archive.len() {
            if let Ok(mut file) = archive.by_index(i) {
                let name = file.name().to_lowercase();

                if name.contains("vba") || name.ends_with("vbaProject.bin") {
                    findings.push("Embedded VBA macro detected".to_string());
                }

                if name.contains("docprops") || name.ends_with(".xml") {
                    let mut content = String::new();
                    if file.read_to_string(&mut content).is_ok() {
                        let lc = content.to_lowercase();
                        for kw in DOCX_SUSPICIOUS_KEYWORDS {
                            if lc.contains(kw) {
                                findings.push(format!("Suspicious keyword '{}' found in metadata or XML", kw));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}


fn analyze_png(data: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    if data.len() > 0 {
        let entropy = calculate_entropy(data);
        if entropy > IMAGE_ENTROPY_THRESHOLD {
            findings.push(format!("High entropy detected in PNG: {:.2}", entropy));
        }
    }

    let string_data = String::from_utf8_lossy(data).to_lowercase();
    for kw in DOCX_SUSPICIOUS_KEYWORDS.iter() {
        if string_data.contains(kw) {
            findings.push(format!("Suspicious keyword '{}' found in PNG", kw));
        }
    }

    findings
}

fn analyze_jpg(data: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    if data.len() > 0 {
        let entropy = calculate_entropy(data);
        if entropy > IMAGE_ENTROPY_THRESHOLD {
            findings.push(format!("High entropy detected in JPG: {:.2}", entropy));
        }
    }

    let string_data = String::from_utf8_lossy(data).to_lowercase();
    for kw in DOCX_SUSPICIOUS_KEYWORDS.iter() {
        if string_data.contains(kw) {
            findings.push(format!("Suspicious keyword '{}' found in JPG", kw));
        }
    }

    findings
}



// New function that works with byte data directly
pub fn analyze_data(data: &[u8]) -> (FileType, AnalysisResult) {
    let file_type = detect_file_type(data);
    
    let result = match file_type {
      FileType::Pdf => match analyze_pdf(data) {
        PdfThreatLevel::Clean => AnalysisResult::Clean,
        PdfThreatLevel::Suspicious(findings) => AnalysisResult::Suspicious(findings),
      },
      FileType::Docx => {
        let findings = analyze_docx(data);
        if findings.is_empty() {
          AnalysisResult::Clean
        } else {
          AnalysisResult::Suspicious(findings)
        }
      },
      FileType::Png => {
        let findings = analyze_png(data);
        if findings.is_empty() {
          AnalysisResult::Clean
        } else {
          AnalysisResult::Suspicious(findings)
        }
      },
      FileType::Jpg => {
        let findings = analyze_jpg(data);
        if findings.is_empty() {
          AnalysisResult::Clean
        } else {
          AnalysisResult::Suspicious(findings)
        }
      },
      _ => AnalysisResult::Clean, // Default to clean for unsupported types
    };
    
    (file_type, result)
  }
  
  // Function to display analysis results
  fn display_analysis_result(data: &[u8]) {
    let (file_type, result) = analyze_data(data);
    
    println!("Detected file type: {:?}", file_type);
    
    match result {
      AnalysisResult::Clean => println!("{:?} Analysis: Clean", file_type),
      AnalysisResult::Suspicious(findings) => {
        println!("{:?} Analysis: Suspicious", file_type);
        for finding in findings {
          println!("- {}", finding);
        }
      }
    }
  }
  