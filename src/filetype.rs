use std::io::Cursor;
use zip::ZipArchive;

#[derive(Debug, PartialEq)]
pub enum FileType {
    Pdf,
    Jpg,
    Png,
    Docx,
    Unknown,
}

pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(b"%PDF") {
        return FileType::Pdf;
    }

    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return FileType::Jpg;
    }

    if data.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n']) {
        return FileType::Png;
    }

    // DOCX (and other Office Open XML formats) are ZIP containers
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        let cursor = Cursor::new(data);
        if let Ok(mut archive) = ZipArchive::new(cursor) {
            for i in 0..archive.len().min(10) {  // Limit to first 10 entries for speed
                if let Ok(file) = archive.by_index(i) {
                    if file.name().eq_ignore_ascii_case("[Content_Types].xml") {
                        return FileType::Docx;
                    }
                }
            }
        }
    }

    FileType::Unknown
}
