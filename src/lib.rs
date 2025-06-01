use wasm_bindgen::prelude::*;
mod filetype;
mod pdf_analysis;

#[wasm_bindgen]
pub fn scan_from_bytes(data: &[u8], source_name: &str) -> JsValue {
  web_sys::console::log_1(&format!("🔍 Analyzing data from: {}", source_name).into());
  
  let (file_type, result) = pdf_analysis::analyze_data(data);
  
  web_sys::console::log_1(&format!("Detected file type: {:?}", file_type).into());
  
  let mut findings = Vec::new();
  let status = match result {
    pdf_analysis::AnalysisResult::Clean => {
      web_sys::console::log_1(&format!("{:?} Analysis: Clean", file_type).into());
      "Clean"
    },
    pdf_analysis::AnalysisResult::Suspicious(detected_findings) => {
      web_sys::console::log_1(&format!("{:?} Analysis: Suspicious", file_type).into());
      for finding in &detected_findings {
        web_sys::console::log_1(&format!("- {}", finding).into());
      }
      findings = detected_findings;
      "Suspicious"
    }
  };
  
  let result_obj = js_sys::Object::new();
  js_sys::Reflect::set(&result_obj, &"fileType".into(), &format!("{:?}", file_type).into()).unwrap();
  js_sys::Reflect::set(&result_obj, &"result".into(), &status.into()).unwrap();
  
  let findings_array = js_sys::Array::new();
  for finding in findings {
    findings_array.push(&finding.into());
  }
  js_sys::Reflect::set(&result_obj, &"findings".into(), &findings_array).unwrap();
  
  result_obj.into()
}