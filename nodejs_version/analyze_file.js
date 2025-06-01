const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const AdmZip = require("adm-zip");

// Constants
const RISK_THRESHOLD = 10;
const ENTROPY_THRESHOLD = 7.9;
const IMAGE_KEYWORDS = ["powershell", "cmd.exe", "wscript", "mimikatz", "dropper", ".ps1"];
const EICAR = "x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*";

// Regex patterns
const patterns = {
  js: /\/\s*\/javascript\s+\/js/i,
  launch: /\/\s*\/launch\s+\/f\s+\(([^)]+)\)/i,
  openAction: /\/openaction\s+<<[^>]*(\/js|\/launch)[^>]*>>/i,
  embeddedFile: /\/embeddedfile|\/filespec/i,
  xfa: /\/xfa/i,
  unc: /\\\\[a-z0-9][a-z0-9_.-]{1,98}[a-z0-9]\\[^\s\\/:*?"<>|]{2,}/i,
  uri: /\/\s*\/uri\s*\/uri\s*\(([^)]+)\)/gi,
};

function calculateEntropy(buffer) {
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    counts[buffer[i]]++;
  }
  const len = buffer.length;
  let entropy = 0;
  for (let count of counts) {
    if (count === 0) continue;
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function analyzePdf(buffer) {
  console.time("Total PDF Analysis");
  const content = buffer.toString("utf8").toLowerCase();
  let findings = [];
  let score = 0;

  const timedCheck = (label, fn) => {
    console.time(label);
    fn();
    console.timeEnd(label);
  };

  timedCheck("JS Regex", () => {
    if (patterns.js.test(content)) {
      findings.push("Embedded JavaScript action detected");
      score += 8;
    }
  });

  timedCheck("Launch Regex", () => {
    const match = content.match(patterns.launch);
    if (match) {
      findings.push(`Launch action to '${match[1]}'`);
      score += match[1].includes(".exe") ? 10 : 5;
    }
  });

  timedCheck("OpenAction Regex", () => {
    if (patterns.openAction.test(content)) {
      findings.push("Executable OpenAction (JS or Launch) detected");
      score += 7;
    }
  });

  timedCheck("Embedded File & XFA", () => {
    if (patterns.embeddedFile.test(content)) {
      findings.push("Embedded file object found");
      score += 5;
    }

    if (patterns.xfa.test(content)) {
      findings.push("XFA form structure detected");
      score += 2;
      if (content.includes("http://") || content.includes("file://") || content.includes("\\\\")) {
        findings.push("External reference in XFA");
        score += 6;
      }
    }
  });

  timedCheck("EICAR Signature", () => {
    if (content.includes(EICAR)) {
      findings.push("EICAR test signature detected");
      score += 10;
    }
  });

  timedCheck("Entropy", () => {
    const entropy = calculateEntropy(buffer);
    if (entropy >= ENTROPY_THRESHOLD) {
      findings.push(`High entropy detected: ${entropy.toFixed(2)}`);
      score += 4;
    }
  });

  timedCheck("UNC Path", () => {
    if (patterns.unc.test(content)) {
      findings.push("UNC path reference detected");
      score += 4;
    }
  });

  timedCheck("Suspicious URI", () => {
    let match;
    while ((match = patterns.uri.exec(content)) !== null) {
      const uri = match[1];
      if (
        uri.startsWith("file://") ||
        uri.startsWith("http://127.") ||
        IMAGE_KEYWORDS.some((kw) => uri.includes(kw))
      ) {
        findings.push(`Suspicious URI action: ${uri}`);
        score += 6;
      }
    }
  });

  console.timeEnd("Total PDF Analysis");
  return { verdict: score >= RISK_THRESHOLD ? "Suspicious" : "Clean", findings, score };
}

function analyzeDocx(buffer) {
  console.time("DOCX Analysis");
  const findings = [];
  try {
    const zip = new AdmZip(buffer);
    const entries = zip.getEntries();
    for (let entry of entries) {
      const name = entry.entryName.toLowerCase();
      if (name.includes("vba") || name.endsWith("vbaproject.bin")) {
        findings.push("Embedded VBA macro detected");
      }
      if (name.includes("docprops") || name.endsWith(".xml")) {
        const content = entry.getData().toString("utf8").toLowerCase();
        IMAGE_KEYWORDS.forEach((kw) => {
          if (content.includes(kw)) {
            findings.push(`Suspicious keyword '${kw}' found in metadata`);
          }
        });
      }
    }
  } catch (err) {
    findings.push("Failed to parse DOCX");
  }
  console.timeEnd("DOCX Analysis");
  return findings;
}

function analyzeImage(buffer, type) {
  console.time(`${type} Analysis`);
  const findings = [];
  const entropy = calculateEntropy(buffer);
  if (entropy >= ENTROPY_THRESHOLD) {
    findings.push(`High entropy detected in ${type}: ${entropy.toFixed(2)}`);
  }
  const content = buffer.toString("utf8").toLowerCase();
  IMAGE_KEYWORDS.forEach((kw) => {
    if (content.includes(kw)) {
      findings.push(`Suspicious keyword '${kw}' found in ${type}`);
    }
  });
  console.timeEnd(`${type} Analysis`);
  return findings;
}

// Determine file type by extension (simple)
function detectFileType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".pdf") return "pdf";
  if (ext === ".docx") return "docx";
  if (ext === ".png") return "png";
  if (ext === ".jpg" || ext === ".jpeg") return "jpg";
  return "unknown";
}

function analyzeFile(filePath) {
  const buffer = fs.readFileSync(filePath);
  const type = detectFileType(filePath);
  console.log(`🔍 Analyzing file: ${filePath}`);
  console.log(`📂 Detected type: ${type.toUpperCase()}`);

  if (type === "pdf") {
    const { verdict, findings, score } = analyzePdf(buffer);
    console.log(`🧪 Verdict: ${verdict} (Score: ${score})`);
    findings.forEach((f) => console.log("- " + f));
  } else if (type === "docx") {
    const findings = analyzeDocx(buffer);
    if (findings.length > 0) {
      console.log("🧪 Verdict: Suspicious");
      findings.forEach((f) => console.log("- " + f));
    } else {
      console.log("🧪 Verdict: Clean");
    }
  } else if (type === "png" || type === "jpg") {
    const findings = analyzeImage(buffer, type);
    if (findings.length > 0) {
      console.log("🧪 Verdict: Suspicious");
      findings.forEach((f) => console.log("- " + f));
    } else {
      console.log("🧪 Verdict: Clean");
    }
  } else {
    console.log("⚠️ Unsupported file type");
  }
}


function isSupportedFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return [".pdf", ".docx", ".jpg", ".jpeg", ".png"].includes(ext);
}

function walkDirectory(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDirectory(fullPath);
    } else if (entry.isFile() && isSupportedFile(fullPath)) {
      try {
        analyzeFile(fullPath);
        console.log("=".repeat(60));
      } catch (err) {
        console.error(`❌ Failed to analyze ${fullPath}: ${err.message}`);
      }
    }
  }
}

// CLI
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    console.error("Usage: node analyze_file.js <file_or_directory>");
    process.exit(1);
  }

  const targetPath = args[0];
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    analyzeFile(targetPath);
  } else if (stat.isDirectory()) {
    walkDirectory(targetPath);
  } else {
    console.error("❌ Provided path is neither file nor directory.");
    process.exit(1);
  }
}
