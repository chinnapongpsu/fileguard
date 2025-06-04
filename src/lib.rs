use wasm_bindgen::prelude::*;
mod filetype;
mod pdf_analysis;

#[wasm_bindgen]
pub fn scan_from_bytes(data: &[u8], source_name: &str) -> JsValue {
    web_sys::console::log_1(&format!("🔍 Analyzing data from: {}", source_name).into());

    // Get the performance object for timing
    let window = web_sys::window().expect("No window object found");
    let performance = window.performance().expect("Performance not available");

    // Start timer
    let start_time = performance.now();

    let (file_type, result) = pdf_analysis::analyze_data(data);

    // End timer and calculate duration
    let end_time = performance.now();
    let duration_ms = end_time - start_time;
    let duration_secs = duration_ms / 1000.0;

    web_sys::console::log_1(&format!("Detected file type: {:?}", file_type).into());
    web_sys::console::log_1(&format!("⏱️ Execution time: {:.3} seconds", duration_secs).into());

    let mut findings = Vec::new();
    let status = match result {
        pdf_analysis::AnalysisResult::Clean => {
            web_sys::console::log_1(&format!("{:?} Analysis: Clean", file_type).into());
            "Clean"
        }
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
    js_sys::Reflect::set(
        &result_obj,
        &"fileType".into(),
        &format!("{:?}", file_type).into(),
    )
    .unwrap();
    js_sys::Reflect::set(&result_obj, &"result".into(), &status.into()).unwrap();
    js_sys::Reflect::set(&result_obj, &"executionTimeMs".into(), &duration_ms.into()).unwrap();
    js_sys::Reflect::set(
        &result_obj,
        &"executionTimeSec".into(),
        &duration_secs.into(),
    )
    .unwrap();

    let findings_array = js_sys::Array::new();
    for finding in findings {
        findings_array.push(&finding.into());
    }
    js_sys::Reflect::set(&result_obj, &"findings".into(), &findings_array).unwrap();

    // Add step timings to the result object
    #[cfg(target_arch = "wasm32")]
    {
        let step_timings = pdf_analysis::get_step_timings();
        let timings_array = js_sys::Array::new();
        for (label, time) in step_timings {
            let timing_obj = js_sys::Object::new();
            js_sys::Reflect::set(&timing_obj, &"label".into(), &label.into()).unwrap();
            js_sys::Reflect::set(&timing_obj, &"timeMs".into(), &time.into()).unwrap();
            timings_array.push(&timing_obj);
        }
        js_sys::Reflect::set(&result_obj, &"stepTimings".into(), &timings_array).unwrap();
    }

    result_obj.into()
}
