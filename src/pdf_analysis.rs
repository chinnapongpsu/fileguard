use std::fs::File;
use std::io::Read;
use std::process;
use regex::Regex;
use zip::ZipArchive;
use std::io::Cursor;


use crate::filetype::{detect_file_type, FileType};


use once_cell::sync::Lazy;


// Precompiled regex definitions
static JS_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/JavaScript\s*/JS").unwrap());
static LAUNCH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/Launch\s*/F\s*\(([^)]+)\)").unwrap());
static OPENACTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"/OpenAction\s*<<[^>]*(/JS|/Launch)[^>]*>>").unwrap());
static UNC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\\\\[a-z0-9][a-z0-9_.-]{1,98}[a-z0-9]\\[^\s\\/:*?"<>|]{2,}"#).unwrap());
static URI_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r#"/URI\s*\(([^)]+)\)"#).unwrap());
const EICAR_SIGNATURE: &[u8] = b"x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*";



// use std::time::Instant;

// Replace the timed_step function with a simple one that just calls the function
fn run_step<F, T>(_label: &str, mut f: F) -> T
where
F: FnMut() -> T,
{
  f()
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

// This function reads from a file path and calls analyze_data
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
  
  // Call the new analyze_data function
  display_analysis_result(&buffer);
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


fn analyze_pdf(data: &[u8]) -> PdfThreatLevel {
  // Only convert visible ASCII and skip binary portions
  let content_str = data.iter()
  .map(|&b| if b.is_ascii() && !b.is_ascii_control() { b as char } else { ' ' })
  .collect::<String>()
  .to_lowercase();
  let content = content_str.as_str();
  let mut findings = Vec::new();
  let mut score = 0;
  
  if run_step("Check JS regex", || JS_REGEX.is_match(content)) {
    findings.push("Embedded JavaScript action detected".to_string());
    score += 8;
  }
  
  run_step("Check Launch regex", || {
    for cap in LAUNCH_REGEX.captures_iter(content) {
      let target = &cap[1];
      findings.push(format!("Launch action to '{}'", target));
      score += if target.contains(".exe") || target.contains("cmd.exe") { 10 } else { 5 };
    }
  });
  
  if run_step("Check OpenAction regex", || OPENACTION_REGEX.is_match(content)) {
    findings.push("Executable OpenAction (JS or Launch) detected".to_string());
    score += 7;
  }
  
  run_step("Check embedded file and object count", || {
    if content.contains("/embeddedfile") || content.contains("/filespec") {
      findings.push("Embedded file object found".to_string());
      score += 5;
    }
    
    let obj_count = content.matches(" obj").count();
    if obj_count > 3000 {
      findings.push(format!("High object count: {}", obj_count));
      score += 3;
    }
  });
  
  run_step("Check XFA & XSLT injection", || {
    if content.contains("/xfa") {
      findings.push("XFA form structure detected".to_string());
      score += 2;
      if content.contains("http://") || content.contains("file://") || content.contains("\\\\") {
        findings.push("External reference in XFA (possible XSLT injection)".to_string());
        score += 6;
      }
    }
  });
  
  if run_step("Check EICAR signature", || {
    data.windows(EICAR_SIGNATURE.len())
    .any(|w| w == EICAR_SIGNATURE)
  }) {
    findings.push("EICAR test signature detected".to_string());
    score += 10;
  }
  
  let entropy = run_step("Calculate entropy", || calculate_entropy(data));
  if entropy >= ENTROPY_SUSPICIOUS_THRESHOLD {
    findings.push(format!("High entropy detected: {:.2}", entropy));
    score += 4;
  }
  
  if run_step("Check UNC path", || UNC_REGEX.is_match(content)) {
    findings.push("UNC path reference detected (network callback possible)".to_string());
    score += 4;
  }
  
  run_step("Check suspicious URI content", || {
    for cap in URI_REGEX.captures_iter(content) {
      let uri = &cap[1].to_lowercase();
      let suspicious_keywords = [
      "mimikatz", "cobaltstrike", "powershell", "dropper", "cmd.exe", "payload", "rat", ".ps1",
      ".vbs", ".bat", ".scr", ".exe",
      ];
      if uri.starts_with("file://")
      || uri.starts_with("http://localhost")
      || uri.starts_with("http://127.")
      || suspicious_keywords.iter().any(|kw| uri.contains(kw))
      {
        findings.push(format!("Suspicious URI action: {}", uri));
        score += 6;
      }
    }
  });
  
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
  
  match ZipArchive::new(cursor) {
    Ok(mut archive) => {
      for i in 0..archive.len() {
        if let Ok(mut file) = archive.by_index(i) {
          let name = file.name().to_lowercase();
          
          if name.contains("vba") || name.ends_with("vbaproject.bin") {
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
    },
    Err(_) => {
      findings.push("Failed to parse DOCX file - possible malformed ZIP structure".to_string());
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
