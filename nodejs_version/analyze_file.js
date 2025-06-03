use std::fs::File;
use std::io::Cursor;
use std::process;
use memmap2::Mmap;
use zip::ZipArchive;

use crate::filetype::{detect_file_type, FileType};

use once_cell::sync::Lazy;
use regex::bytes::Regex;

static JS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/javascript").unwrap());
static LAUNCH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/launch\\s*\\(([^)]+)\\)").unwrap());
static OPENACTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/openaction\\s*<<[^>]*(/js|/launch)[^>]*>>").unwrap());
static UNC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\\\\[a-z0-9][a-z0-9_.-]{1,98}\\[^"]*?").unwrap());
static URI_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)/uri\\s*/uri\\s*\\(([^)]+)\\)").unwrap());

const EICAR_SIGNATURE: &[u8] = b"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*";
const ENTROPY_SUSPICIOUS_THRESHOLD: f64 = 7.9;
const RISK_THRESHOLD: u32 = 10;
const IMAGE_ENTROPY_THRESHOLD: f64 = 7.9;
const DOCX_SUSPICIOUS_KEYWORDS: [&str; 6] = [
    "powershell", "cmd.exe", "wscript", "mimikatz", "dropper", ".ps1",
];

#[derive(Debug)]
pub enum PdfThreatLevel {
    Clean,
    Suspicious(Vec<String>),
}

pub fn analyze_file(file_path: &str) {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            process::exit(1);
        }
    };

    let mmap = unsafe { Mmap::map(&file).expect("Failed to memory map file") };
    let buffer = &mmap[..];

    let file_type = detect_file_type(buffer);
    println!("Detected file type: {:?}", file_type);

    match file_type {
        FileType::Pdf => match analyze_pdf(buffer) {
            PdfThreatLevel::Clean => println!("PDF Analysis: Clean"),
            PdfThreatLevel::Suspicious(f) => {
                println!("PDF Analysis: Suspicious");
                for ff in f {
                    println!("- {}", ff);
                }
            }
        },
        FileType::Docx => {
            let findings = analyze_docx(buffer);
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
            let findings = analyze_image(buffer, "PNG");
            for f in findings {
                println!("- {}", f);
            }
        }
        FileType::Jpg => {
            let findings = analyze_image(buffer, "JPG");
            for f in findings {
                println!("- {}", f);
            }
        }
        _ => println!("Unsupported or unknown file type."),
    }
}

pub fn analyze_pdf(data: &[u8]) -> PdfThreatLevel {
    let mut findings = Vec::new();
    let mut score = 0;

    if JS_REGEX.is_match(data) {
        findings.push("Embedded JavaScript action detected".to_string());
        score += 8;
    }

    for cap in LAUNCH_REGEX.captures_iter(data) {
        if let Some(target) = cap.get(1) {
            let t = String::from_utf8_lossy(target.as_bytes());
            findings.push(format!("Launch action to '{}'", t));
            score += if t.contains(".exe") || t.contains("cmd.exe") { 10 } else { 5 };
        }
    }

    if OPENACTION_REGEX.is_match(data) {
        findings.push("Executable OpenAction (JS or Launch) detected".to_string());
        score += 7;
    }

    if data.windows(13).any(|w| w.eq_ignore_ascii_case(b"/embeddedfile"))
        || data.windows(9).any(|w| w.eq_ignore_ascii_case(b"/filespec")) {
        findings.push("Embedded file object found".to_string());
        score += 5;
    }

    let obj_count = data.windows(4).filter(|w| *w == b" obj").count();
    if obj_count > 3000 {
        findings.push(format!("High object count: {}", obj_count));
        score += 3;
    }

    if data.windows(4).any(|w| w.eq_ignore_ascii_case(b"/xfa")) {
        findings.push("XFA form structure detected".to_string());
        score += 2;
        if data.windows(7).any(|w| w.eq_ignore_ascii_case(b"http://"))
            || data.windows(7).any(|w| w.eq_ignore_ascii_case(b"file://"))
            || data.windows(2).any(|w| w == b"\\") {
            findings.push("External reference in XFA (possible XSLT injection)".to_string());
            score += 6;
        }
    }

    if data.windows(EICAR_SIGNATURE.len()).any(|w| w.eq_ignore_ascii_case(EICAR_SIGNATURE)) {
        findings.push("EICAR test signature detected".to_string());
        score += 10;
    }

    let entropy = calculate_entropy(data);
    if entropy >= ENTROPY_SUSPICIOUS_THRESHOLD {
        findings.push(format!("High entropy detected: {:.2}", entropy));
        score += 4;
    }

    if UNC_REGEX.is_match(data) {
        findings.push("UNC path reference detected (network callback possible)".to_string());
        score += 4;
    }

    for cap in URI_REGEX.captures_iter(data) {
        if let Some(uri) = cap.get(1) {
            let u = String::from_utf8_lossy(uri.as_bytes()).to_lowercase();
            let suspicious_keywords = ["mimikatz", "cobaltstrike", "powershell", "dropper", "cmd.exe", "payload", "rat", ".ps1", ".vbs", ".bat", ".scr", ".exe"];
            if u.starts_with("file://") || u.starts_with("http://localhost") || u.starts_with("http://127.") || suspicious_keywords.iter().any(|kw| u.contains(kw)) {
                findings.push(format!("Suspicious URI action: {}", u));
                score += 6;
            }
        }
    }

    if score >= RISK_THRESHOLD {
        findings.push(format!("⚠️ Risk score = {} (threshold = {})", score, RISK_THRESHOLD));
        PdfThreatLevel::Suspicious(findings)
    } else {
        PdfThreatLevel::Clean
    }
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
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

pub fn analyze_docx(data: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    let cursor = Cursor::new(data);
    if let Ok(mut archive) = ZipArchive::new(cursor) {
        for i in 0..archive.len() {
            if let Ok(mut file) = archive.by_index(i) {
                let name = file.name().to_lowercase();
                if name.contains("vba") || name.ends_with("vbaproject.bin") {
                    findings.push("Embedded VBA macro detected".to_string());
                }
                if name.contains("docprops") || name.ends_with(".xml") {
                    let mut content = String::new();
                    if file.read_to_string(&mut content).is_ok() {
                        for kw in &DOCX_SUSPICIOUS_KEYWORDS {
                            if content.to_lowercase().contains(kw) {
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

pub fn analyze_image(data: &[u8], label: &str) -> Vec<String> {
    let mut findings = Vec::new();
    if !data.is_empty() {
        let entropy = calculate_entropy(data);
        if entropy > IMAGE_ENTROPY_THRESHOLD {
            findings.push(format!("High entropy detected in {}: {:.2}", label, entropy));
        }
    }
    findings
}
