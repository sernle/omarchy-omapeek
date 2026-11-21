//! OmaPeek Inspector & Offline Static Safety Analyzer (Pure Rust, zero dependencies).
//! Streams large files in fixed buffers for sub-millisecond startup and minimal RAM usage.

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

const MAX_TEXT_BYTES: usize = 128 * 1024;
const MAX_SCAN_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 500;
const ZIP_BOMB_RATIO: f64 = 100.0;
const ZIP_BOMB_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

const IMAGE_EXTS: &[&str] = &[".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico", ".avif"];
const AUDIO_EXTS: &[&str] = &[".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".opus"];
const VIDEO_EXTS: &[&str] = &[".mp4", ".mkv", ".webm", ".mov", ".avi", ".m4v"];
const MARKDOWN_EXTS: &[&str] = &[".md", ".markdown", ".mdx"];
const PDF_EXTS: &[&str] = &[".pdf"];
const ARCHIVE_EXTS: &[&str] = &[".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".whl", ".jar"];
const CODE_EXTS: &[&str] = &[
    ".py", ".js", ".ts", ".tsx", ".jsx", ".qml", ".sh", ".bash", ".zsh", ".fish",
    ".rs", ".go", ".c", ".h", ".cpp", ".hpp", ".java", ".kt", ".swift", ".rb",
    ".php", ".lua", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".xml", ".html", ".htm", ".css", ".scss", ".sql", ".dockerfile", ".env",
    ".txt", ".log", ".csv", ".gitignore", ".nix", ".vim",
];
const EXECUTABLE_EXTS: &[&str] = &[
    ".sh", ".bash", ".zsh", ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".msi", ".appimage", ".run", ".bin", ".elf", ".dmg", ".pkg", ".command",
    ".scr", ".com", ".jar", ".deb", ".rpm",
];

// ============================================================================
// Minimal JSON Escaping Helpers (zero external crates)
// ============================================================================

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt_str(s: &Option<String>) -> String {
    match s {
        Some(v) => json_escape(v),
        None => "null".to_string(),
    }
}

fn json_opt_u64(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

// ============================================================================
// Pure-Rust Streaming SHA-256 (FIPS 180-4)
// ============================================================================

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 64 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::compress(&mut self.state, &block);
            offset += 64;
        }
        if offset < data.len() {
            let rem = data.len() - offset;
            self.buf[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            Self::compress(&mut self.state, &block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        Self::compress(&mut self.state, &block);

        let mut out = String::with_capacity(64);
        for word in self.state {
            out.push_str(&format!("{:08x}", word));
        }
        out
    }
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

// ============================================================================
// Data Structures
// ============================================================================

struct Finding {
    severity: String,
    code: String,
    title: String,
    detail: String,
}

impl Finding {
    fn new(severity: &str, code: &str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: severity.to_string(),
            code: code.to_string(),
            title: title.into(),
            detail: detail.into(),
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"severity\":{},\"code\":{},\"title\":{},\"detail\":{}}}",
            json_escape(&self.severity),
            json_escape(&self.code),
            json_escape(&self.title),
            json_escape(&self.detail),
        )
    }
}

struct CustomRule {
    severity: String,
    code: String,
    extensions: Vec<String>,
    needle_lower: String,
    title: String,
    detail: String,
}

fn load_custom_rules() -> Vec<CustomRule> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();

    // 1. Built-in plugin rules (<plugin_dir>/rules/community.rules)
    if let Ok(exe) = env::current_exe() {
        if let Some(plugin_dir) = exe.parent().and_then(|p| p.parent()) {
            let p = plugin_dir.join("rules").join("community.rules");
            if p.exists() {
                paths.push(p);
            }
        }
    }
    // 2. User rules (~/.config/omarchy/omapeek.rules)
    if let Ok(home) = env::var("HOME") {
        let p = Path::new(&home).join(".config/omarchy/omapeek.rules");
        if p.exists() {
            paths.push(p);
        }
    }
    // 3. Explicit OMAPEEK_RULES override
    if let Ok(custom) = env::var("OMAPEEK_RULES") {
        let p = Path::new(&custom).to_path_buf();
        if p.exists() {
            paths.push(p);
        }
    }

    let mut rules = Vec::new();
    for p in paths {
        let Ok(content) = fs::read_to_string(&p) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(6, '|').collect();
            if parts.len() < 6 {
                continue;
            }
            let sev = parts[0].trim().to_ascii_lowercase();
            if !matches!(sev.as_str(), "high" | "medium" | "low" | "info") {
                continue;
            }
            let exts: Vec<String> = parts[2]
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            let needle = parts[3].trim().to_ascii_lowercase();
            if needle.is_empty() {
                continue;
            }
            rules.push(CustomRule {
                severity: sev,
                code: parts[1].trim().to_string(),
                extensions: exts,
                needle_lower: needle,
                title: parts[4].trim().to_string(),
                detail: parts[5].trim().to_string(),
            });
        }
    }
    rules
}

struct ArchiveEntry {
    name: String,
    is_dir: bool,
    size: u64,
    compressed_size: Option<u64>,
    flags: Vec<&'static str>,
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    for (i, unit) in UNITS.iter().enumerate() {
        if val < 1024.0 || i == UNITS.len() - 1 {
            return if i == 0 {
                format!("{} {}", bytes, unit)
            } else {
                format!("{:.1} {}", val, unit)
            };
        }
        val /= 1024.0;
    }
    format!("{} B", bytes)
}

fn detect_magic(header: &[u8]) -> Option<(&'static str, &'static str)> {
    let sigs: &[(&[u8], &str, &str)] = &[
        (b"\x7fELF", "elf", "Linux ELF executable"),
        (b"\xcf\xfa\xed\xfe", "macho", "macOS Mach-O executable"),
        (b"\xfe\xed\xfa\xcf", "macho", "macOS Mach-O executable"),
        (b"\xca\xfe\xba\xbe", "macho", "Universal Mach-O / Java class"),
        (b"MZ", "pe", "Windows PE/EXE executable"),
        (b"%PDF-", "pdf", "PDF document"),
        (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
        (b"\xff\xd8\xff", "jpeg", "JPEG image"),
        (b"GIF87a", "gif", "GIF image"),
        (b"GIF89a", "gif", "GIF image"),
        (b"PK\x03\x04", "zip", "ZIP archive"),
        (b"PK\x05\x06", "zip", "Empty ZIP archive"),
        (b"\x1f\x8b", "gzip", "GZIP archive"),
        (b"BZh", "bzip2", "BZIP2 archive"),
        (b"\xfd7zXZ\x00", "xz", "XZ archive"),
        (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
        (b"ID3", "mp3", "MP3 audio"),
        (b"\xff\xfb", "mp3", "MP3 audio"),
        (b"fLaC", "flac", "FLAC lossless audio"),
        (b"OggS", "ogg", "Ogg media container"),
        (b"\x1a\x45\xdf\xa3", "mkv", "Matroska / WebM video"),
        (b"#!", "shebang", "Executable script (shebang)"),
    ];
    for (sig, tag, label) in sigs {
        if header.starts_with(sig) {
            return Some((tag, label));
        }
    }
    if header.len() >= 12 && &header[0..4] == b"RIFF" {
        if &header[8..12] == b"WEBP" {
            return Some(("webp", "WebP image"));
        }
        if &header[8..12] == b"WAVE" {
            return Some(("wav", "WAV audio"));
        }
        if &header[8..12] == b"AVI " {
            return Some(("avi", "AVI video"));
        }
    }
    if header.len() >= 12 && &header[4..8] == b"ftyp" {
        let brand = &header[8..12];
        if brand == b"M4A " {
            return Some(("m4a", "M4A audio"));
        }
        return Some(("mp4", "MP4 / MOV video"));
    }
    let trimmed = std::str::from_utf8(&header[..header.len().min(512)]).unwrap_or("").trim_start();
    if trimmed.starts_with("<svg") || (trimmed.starts_with("<?xml") && trimmed.contains("<svg")) {
        return Some(("svg", "SVG vector image"));
    }
    None
}

fn is_probably_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let sample = &data[..data.len().min(8192)];
    if sample.contains(&0u8) {
        return false;
    }
    std::str::from_utf8(sample).is_ok()
}

fn file_suffixes(name: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let trimmed = name.trim_start_matches('.');
    for seg in trimmed.split('.').skip(1) {
        if !seg.is_empty() {
            parts.push(format!(".{}", seg.to_ascii_lowercase()));
        }
    }
    parts
}

fn is_double_ext(name: &str) -> Option<String> {
    let suffixes = file_suffixes(name);
    if suffixes.len() >= 2 {
        let last = suffixes[suffixes.len() - 1].as_str();
        let prev = suffixes[suffixes.len() - 2].as_str();
        let passive = IMAGE_EXTS.contains(&prev)
            || PDF_EXTS.contains(&prev)
            || matches!(prev, ".doc" | ".docx" | ".xls" | ".txt");
        if EXECUTABLE_EXTS.contains(&last) && passive {
            return Some(format!("{}{}", prev, last));
        }
    }
    None
}

fn mime_for_ext(ext: &str) -> &'static str {
    match ext {
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".svg" => "image/svg+xml",
        ".mp3" => "audio/mpeg",
        ".wav" => "audio/wav",
        ".flac" => "audio/flac",
        ".ogg" | ".opus" => "audio/ogg",
        ".m4a" | ".aac" => "audio/mp4",
        ".mp4" | ".m4v" => "video/mp4",
        ".webm" => "video/webm",
        ".mkv" => "video/x-matroska",
        ".mov" => "video/quicktime",
        ".avi" => "video/x-msvideo",
        ".pdf" => "application/pdf",
        ".zip" => "application/zip",
        ".tar" => "application/x-tar",
        ".gz" | ".tgz" => "application/gzip",
        ".md" | ".markdown" => "text/markdown",
        ".json" => "application/json",
        ".py" => "text/x-python",
        ".rs" => "text/x-rust",
        ".sh" | ".bash" | ".zsh" => "text/x-shellscript",
        ".txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

// ============================================================================
// General Safety Checks
// ============================================================================

fn check_general_safety(
    name: &str,
    ext: &str,
    magic: Option<(&str, &str)>,
    executable: bool,
    findings: &mut Vec<Finding>,
) {
    // 1. Unicode Right-to-Left Override spoofing
    if name.chars().any(|c| matches!(c, '\u{202e}' | '\u{202d}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}')) {
        findings.push(Finding::new(
            "high",
            "RLO_SPOOF",
            "Unicode bidi override in filename",
            "Filename contains invisible Right-to-Left Override characters commonly used to disguise executable extensions.",
        ));
    }

    // 2. Double extension
    if let Some(dbl) = is_double_ext(name) {
        findings.push(Finding::new(
            "high",
            "DOUBLE_EXTENSION",
            format!("Suspicious double extension ({})", dbl),
            format!("File pretends to be a passive document/image but ends in an executable extension ({}).", dbl),
        ));
    }

    // 3. Magic-byte vs extension spoofing
    if let Some((tag, label)) = magic {
        if IMAGE_EXTS.contains(&ext) && matches!(tag, "elf" | "macho" | "pe" | "shebang" | "zip" | "pdf") {
            findings.push(Finding::new(
                "high",
                "EXTENSION_SPOOF",
                format!("Disguised file: `{}` is actually {}", ext, label),
                format!("File extension claims to be an image (`{}`), but its header bytes match {}.", ext, label),
            ));
        } else if PDF_EXTS.contains(&ext) && matches!(tag, "elf" | "macho" | "pe" | "shebang" | "zip") {
            findings.push(Finding::new(
                "high",
                "EXTENSION_SPOOF",
                format!("Disguised file: `.pdf` is actually {}", label),
                format!("File claims to be a PDF, but its header bytes match {}.", label),
            ));
        } else if (AUDIO_EXTS.contains(&ext) || VIDEO_EXTS.contains(&ext)) && matches!(tag, "elf" | "macho" | "pe" | "shebang") {
            findings.push(Finding::new(
                "high",
                "EXTENSION_SPOOF",
                format!("Disguised media file: `{}` is actually {}", ext, label),
                format!("File extension claims to be media (`{}`), but its header bytes match {}.", ext, label),
            ));
        }
    }

    // 4. Executable bit on passive files
    if executable && (IMAGE_EXTS.contains(&ext) || PDF_EXTS.contains(&ext) || MARKDOWN_EXTS.contains(&ext) || AUDIO_EXTS.contains(&ext) || VIDEO_EXTS.contains(&ext)) {
        findings.push(Finding::new(
            "medium",
            "UNEXPECTED_EXEC_BIT",
            "Executable permission bit is set",
            format!("Passive file type (`{}`) has Unix execute permissions (`+x`).", ext),
        ));
    }
}

// ============================================================================
// Streaming ZIP Central Directory Inspector (O(central_dir) memory!)
// ============================================================================

fn read_u16_le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn inspect_zip_streaming(path: &Path, findings: &mut Vec<Finding>) -> io::Result<String> {
    let mut f = File::open(path)?;
    let file_len = f.metadata()?.len();
    let tail_len = file_len.min(65557) as usize;
    f.seek(SeekFrom::Start(file_len - tail_len as u64))?;
    let mut tail = vec![0u8; tail_len];
    f.read_exact(&mut tail)?;

    // Locate End of Central Directory (PK\x05\x06) from the end
    let eocd_pos = (0..=tail_len.saturating_sub(22))
        .rev()
        .find(|&i| &tail[i..i + 4] == b"PK\x05\x06")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ZIP EOCD signature not found"))?;

    let cd_size = read_u32_le(&tail, eocd_pos + 12) as u64;
    let cd_offset = read_u32_le(&tail, eocd_pos + 16) as u64;
    let total_entries_hdr = read_u16_le(&tail, eocd_pos + 10) as usize;

    let mut entries: Vec<ArchiveEntry> = Vec::new();
    let mut total_compressed: u64 = 0;
    let mut total_uncompressed: u64 = 0;
    let mut total_count: usize = 0;

    let mut zip_slip_hits: Vec<String> = Vec::new();
    let mut exec_hits: Vec<String> = Vec::new();
    let mut double_ext_hits: Vec<String> = Vec::new();
    let mut symlink_hits: Vec<String> = Vec::new();
    let mut encrypted_count: usize = 0;

    // Read Central Directory (bounded to 16 MB for safety)
    let read_cd_len = cd_size.min(16 * 1024 * 1024) as usize;
    if cd_offset + read_cd_len as u64 <= file_len {
        f.seek(SeekFrom::Start(cd_offset))?;
        let mut cd = vec![0u8; read_cd_len];
        f.read_exact(&mut cd)?;

        let mut pos = 0usize;
        while pos + 46 <= cd.len() && &cd[pos..pos + 4] == b"PK\x01\x02" {
            let gp_flags = read_u16_le(&cd, pos + 8);
            let comp_size = read_u32_le(&cd, pos + 20) as u64;
            let uncomp_size = read_u32_le(&cd, pos + 24) as u64;
            let name_len = read_u16_le(&cd, pos + 28) as usize;
            let extra_len = read_u16_le(&cd, pos + 30) as usize;
            let comment_len = read_u16_le(&cd, pos + 32) as usize;
            let ext_attr = read_u32_le(&cd, pos + 38);

            if pos + 46 + name_len > cd.len() {
                break;
            }
            let name = String::from_utf8_lossy(&cd[pos + 46..pos + 46 + name_len]).to_string();
            pos += 46 + name_len + extra_len + comment_len;

            total_count += 1;
            total_compressed = total_compressed.saturating_add(comp_size);
            total_uncompressed = total_uncompressed.saturating_add(uncomp_size);

            let is_dir = name.ends_with('/');
            let norm = name.replace('\\', "/");
            let mut flags: Vec<&'static str> = Vec::new();

            if norm.starts_with('/') || norm.split('/').any(|p| p == "..") {
                zip_slip_hits.push(name.clone());
                flags.push("zip-slip");
            }
            if (gp_flags & 0x1) != 0 {
                encrypted_count += 1;
                flags.push("encrypted");
            }
            let unix_mode = (ext_attr >> 16) & 0o170000;
            if unix_mode == 0o120000 {
                symlink_hits.push(name.clone());
                flags.push("symlink");
            }
            if !is_dir {
                let file_name = Path::new(&norm).file_name().and_then(|s| s.to_str()).unwrap_or("");
                let ext = Path::new(file_name)
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
                    .unwrap_or_default();
                if EXECUTABLE_EXTS.contains(&ext.as_str()) {
                    exec_hits.push(name.clone());
                    flags.push("executable");
                }
                if is_double_ext(file_name).is_some() {
                    double_ext_hits.push(name.clone());
                    flags.push("double-ext");
                }
            }

            if entries.len() < MAX_ARCHIVE_ENTRIES {
                entries.push(ArchiveEntry {
                    name,
                    is_dir,
                    size: uncomp_size,
                    compressed_size: Some(comp_size),
                    flags,
                });
            }
        }
    }

    if total_count == 0 {
        total_count = total_entries_hdr;
    }

    let ratio = if total_compressed > 0 {
        total_uncompressed as f64 / total_compressed as f64
    } else {
        1.0
    };

    emit_archive_findings(
        findings,
        &zip_slip_hits,
        &double_ext_hits,
        &exec_hits,
        &symlink_hits,
        encrypted_count,
        ratio,
        total_uncompressed,
    );

    Ok(format_archive_json(
        "zip",
        total_count,
        total_uncompressed,
        ratio,
        &entries,
    ))
}

fn inspect_tar_via_cli(path: &Path, findings: &mut Vec<Finding>) -> io::Result<String> {
    // Use system `tar -tvf` for compressed tarballs (.tar.gz/.tar.xz/.tar.bz2) without pulling compression crates
    let out = Command::new("tar")
        .arg("-tvf")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut entries: Vec<ArchiveEntry> = Vec::new();
    let mut total_uncompressed: u64 = 0;
    let mut total_count: usize = 0;
    let mut zip_slip_hits = Vec::new();
    let mut exec_hits = Vec::new();
    let mut double_ext_hits = Vec::new();
    let mut symlink_hits = Vec::new();

    for line in listing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let mode = parts[0];
        let is_dir = mode.starts_with('d');
        let is_sym = mode.starts_with('l');
        let size: u64 = parts.iter().find_map(|p| p.parse::<u64>().ok()).unwrap_or(0);
        let name = parts.last().copied().unwrap_or("").to_string();

        total_count += 1;
        total_uncompressed = total_uncompressed.saturating_add(size);

        let mut flags = Vec::new();
        if name.starts_with('/') || name.split('/').any(|p| p == "..") {
            zip_slip_hits.push(name.clone());
            flags.push("zip-slip");
        }
        if is_sym {
            symlink_hits.push(name.clone());
            flags.push("symlink");
        }
        if !is_dir {
            let ext = Path::new(&name)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
                .unwrap_or_default();
            if EXECUTABLE_EXTS.contains(&ext.as_str()) {
                exec_hits.push(name.clone());
                flags.push("executable");
            }
            if is_double_ext(&name).is_some() {
                double_ext_hits.push(name.clone());
                flags.push("double-ext");
            }
        }
        if entries.len() < MAX_ARCHIVE_ENTRIES {
            entries.push(ArchiveEntry {
                name,
                is_dir,
                size,
                compressed_size: None,
                flags,
            });
        }
    }

    let comp_size = fs::metadata(path).map(|m| m.len()).unwrap_or(1).max(1);
    let ratio = total_uncompressed as f64 / comp_size as f64;

    emit_archive_findings(
        findings,
        &zip_slip_hits,
        &double_ext_hits,
        &exec_hits,
        &symlink_hits,
        0,
        ratio,
        total_uncompressed,
    );

    Ok(format_archive_json("tar", total_count, total_uncompressed, ratio, &entries))
}

#[allow(clippy::too_many_arguments)]
fn emit_archive_findings(
    findings: &mut Vec<Finding>,
    zip_slip_hits: &[String],
    double_ext_hits: &[String],
    exec_hits: &[String],
    symlink_hits: &[String],
    encrypted_count: usize,
    ratio: f64,
    total_uncompressed: u64,
) {
    if !zip_slip_hits.is_empty() {
        findings.push(Finding::new(
            "high",
            "ZIP_SLIP",
            format!("Path traversal (Zip-Slip) in {} entr{}", zip_slip_hits.len(), if zip_slip_hits.len() == 1 { "y" } else { "ies" }),
            format!("Archive writes outside target directory: {}", zip_slip_hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
        ));
    }
    if ratio >= ZIP_BOMB_RATIO || total_uncompressed >= ZIP_BOMB_UNCOMPRESSED_BYTES {
        findings.push(Finding::new(
            "high",
            "ZIP_BOMB",
            format!("Possible zip bomb ({:.0}x ratio, {} unpacked)", ratio, human_size(total_uncompressed)),
            "Extreme compression ratio or uncompressed size could exhaust disk space on extraction.",
        ));
    }
    if !double_ext_hits.is_empty() {
        findings.push(Finding::new(
            "high",
            "ARCHIVE_DOUBLE_EXT",
            "Disguised double-extension file inside archive",
            format!("Suspicious entry: {}", double_ext_hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
        ));
    }
    if !exec_hits.is_empty() {
        findings.push(Finding::new(
            "medium",
            "ARCHIVE_EXECUTABLES",
            format!("Contains {} executable/script file(s)", exec_hits.len()),
            format!("Inspect before running: {}", exec_hits.iter().take(4).cloned().collect::<Vec<_>>().join(", ")),
        ));
    }
    if !symlink_hits.is_empty() {
        findings.push(Finding::new(
            "medium",
            "ARCHIVE_SYMLINKS",
            format!("Contains {} symlink(s)", symlink_hits.len()),
            format!("Symlinks can point outside the extraction directory: {}", symlink_hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
        ));
    }
    if encrypted_count > 0 {
        findings.push(Finding::new(
            "low",
            "ARCHIVE_ENCRYPTED",
            format!("{} password-protected entr{}", encrypted_count, if encrypted_count == 1 { "y" } else { "ies" }),
            "Encrypted archive contents cannot be statically scanned before extraction.",
        ));
    }
}

fn format_archive_json(
    archive_type: &str,
    entry_count: usize,
    total_uncompressed: u64,
    ratio: f64,
    entries: &[ArchiveEntry],
) -> String {
    let entries_json: Vec<String> = entries
        .iter()
        .map(|e| {
            let flags_json: Vec<String> = e.flags.iter().map(|f| json_escape(f)).collect();
            format!(
                "{{\"name\":{},\"is_dir\":{},\"size\":{},\"compressed_size\":{},\"flags\":[{}]}}",
                json_escape(&e.name),
                e.is_dir,
                e.size,
                json_opt_u64(e.compressed_size),
                flags_json.join(",")
            )
        })
        .collect();
    format!(
        "{{\"archive_type\":{},\"entry_count\":{},\"truncated\":{},\"total_uncompressed\":{},\"total_uncompressed_human\":{},\"compression_ratio\":{:.2},\"entries\":[{}]}}",
        json_escape(archive_type),
        entry_count,
        entry_count > MAX_ARCHIVE_ENTRIES,
        total_uncompressed,
        json_escape(&human_size(total_uncompressed)),
        ratio,
        entries_json.join(",")
    )
}

// ============================================================================
// PDF Inspector (Bounded Memory)
// ============================================================================

fn render_pdf_thumbnail(path: &Path, sha_prefix: &str) -> Option<String> {
    let thumb_dir = env::temp_dir().join("omapeek-thumbs");
    let _ = fs::create_dir_all(&thumb_dir);
    let out_prefix = thumb_dir.join(sha_prefix);
    let out_png = thumb_dir.join(format!("{}.png", sha_prefix));
    if out_png.exists() {
        return Some(out_png.to_string_lossy().to_string());
    }

    // 1. Linux / Arch (poppler): pdftoppm -png -f 1 -l 1 -singlefile -scale-to 900
    if let Ok(status) = Command::new("pdftoppm")
        .args(["-png", "-f", "1", "-l", "1", "-singlefile", "-scale-to", "900"])
        .arg(path)
        .arg(&out_prefix)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        if status.success() && out_png.exists() {
            return Some(out_png.to_string_lossy().to_string());
        }
    }

    // 2. macOS fallback: qlmanage -t -s 900 -o <thumb_dir> <path>
    if let Ok(status) = Command::new("qlmanage")
        .args(["-t", "-s", "900", "-o"])
        .arg(&thumb_dir)
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        if status.success() {
            if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                let ql_out = thumb_dir.join(format!("{}.png", fname));
                if ql_out.exists() {
                    let _ = fs::rename(&ql_out, &out_png);
                    if out_png.exists() {
                        return Some(out_png.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    None
}

fn inspect_pdf(path: &Path, sha_prefix: &str, findings: &mut Vec<Finding>) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut raw = Vec::new();
    f.by_ref().take(MAX_SCAN_BYTES as u64).read_to_end(&mut raw)?;

    let version = if raw.starts_with(b"%PDF-") {
        let head = String::from_utf8_lossy(&raw[5..raw.len().min(12)]);
        head.lines().next().unwrap_or("unknown").trim().to_string()
    } else {
        "unknown".to_string()
    };

    // Count /Type /Page (excluding /Type /Pages)
    let mut page_count = 0usize;
    let mut idx = 0usize;
    while let Some(pos) = find_bytes(&raw[idx..], b"/Type") {
        let after = &raw[idx + pos + 5..];
        let trimmed_start = after.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(after.len());
        let rest = &after[trimmed_start..];
        if rest.starts_with(b"/Page") && !rest.starts_with(b"/Pages") {
            page_count += 1;
        }
        idx += pos + 5;
    }
    if page_count == 0 && raw.starts_with(b"%PDF-") {
        page_count = 1;
    }

    let checks: &[(&str, &str, &[&[u8]], &str, &str)] = &[
        ("high", "PDF_JAVASCRIPT", &[b"/JavaScript", b"/JS"], "Embedded JavaScript in PDF", "PDF contains `/JavaScript` or `/JS` actions that can execute scripts in vulnerable readers."),
        ("high", "PDF_LAUNCH", &[b"/Launch"], "External command `/Launch` action", "PDF attempts to launch an external program or file."),
        ("medium", "PDF_OPENACTION", &[b"/OpenAction", b"/AA"], "Auto-execute action on open (`/OpenAction`)", "PDF defines an automatic action triggered immediately when opened."),
        ("medium", "PDF_EMBEDDED_FILE", &[b"/EmbeddedFile"], "Contains embedded file attachment", "PDF embeds another file inside its object stream."),
        ("low", "PDF_EXTERNAL_URI", &[b"/URI", b"/SubmitForm"], "External URLs or form submission", "PDF references external links (`/URI`) or remote form submission (`/SubmitForm`)."),
    ];
    for (sev, code, needles, title, detail) in checks {
        if needles.iter().any(|n| find_bytes(&raw, n).is_some()) {
            findings.push(Finding::new(sev, code, *title, *detail));
        }
    }

    // Extract /Title (...)
    let title = find_bytes(&raw, b"/Title").and_then(|pos| {
        let rest = &raw[pos + 6..raw.len().min(pos + 200)];
        let open = rest.iter().position(|&b| b == b'(')?;
        let close = rest[open + 1..].iter().position(|&b| b == b')')?;
        Some(String::from_utf8_lossy(&rest[open + 1..open + 1 + close]).to_string())
    });

    let thumbnail = render_pdf_thumbnail(path, sha_prefix);

    Ok(format!(
        "{{\"version\":{},\"page_count\":{},\"title\":{},\"thumbnail\":{}}}",
        json_escape(&version),
        page_count,
        json_opt_str(&title),
        json_opt_str(&thumbnail)
    ))
}

// ============================================================================
// Code / Markdown Inspector (Bounded Memory)
// ============================================================================

fn inspect_code(path: &Path, ext: &str, custom_rules: &[CustomRule], findings: &mut Vec<Finding>) -> io::Result<String> {
    let total_size = fs::metadata(path)?.len() as usize;
    let mut f = File::open(path)?;
    let mut scan_buf = Vec::new();
    f.by_ref().take(MAX_SCAN_BYTES as u64).read_to_end(&mut scan_buf)?;

    let scan_text = String::from_utf8_lossy(&scan_buf);
    let truncated = total_size > MAX_TEXT_BYTES;
    let preview_bytes = &scan_buf[..scan_buf.len().min(MAX_TEXT_BYTES)];
    let preview_text = String::from_utf8_lossy(preview_bytes);
    let line_count = preview_text.lines().count();

    // Fast line-by-line heuristic checks
    let mut hit_pipe = false;
    let mut hit_b64 = false;
    let mut hit_revshell = false;
    let mut hit_rm = false;
    let mut hit_cred = false;
    let mut hit_persist = false;
    let mut hit_eval = false;
    let mut longest_line = 0usize;

    for line in scan_text.lines() {
        if line.len() > longest_line {
            longest_line = line.len();
        }
        let lower = line.to_ascii_lowercase();
        if !hit_pipe && (lower.contains("curl ") || lower.contains("wget ")) && (lower.contains("| sh") || lower.contains("| bash") || lower.contains("| zsh") || lower.contains("| sudo sh") || lower.contains("| sudo bash")) {
            hit_pipe = true;
            findings.push(Finding::new(
                "high",
                "PIPE_TO_SHELL",
                "Remote download piped directly to shell",
                format!("Executes untrusted remote code directly. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_b64 && ((lower.contains("base64") && (lower.contains(" -d") || lower.contains("--decode")) && lower.contains('|')) || lower.contains("eval $(") || lower.contains("eval \"$(")) {
            hit_b64 = true;
            findings.push(Finding::new(
                "high",
                "BASE64_EXEC",
                "Obfuscated Base64 / eval payload execution",
                format!("Decodes or evaluates obfuscated shell payload. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_revshell && (lower.contains("/dev/tcp/") || lower.contains("bash -i >&") || (lower.contains("nc ") && lower.contains(" -e "))) {
            hit_revshell = true;
            findings.push(Finding::new(
                "high",
                "REVERSE_SHELL",
                "Reverse shell pattern detected",
                format!("Interactive network shell redirection detected. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_rm && (lower.contains("rm -rf /") || lower.contains("rm -fr /") || lower.contains("rm -rf ~")) {
            hit_rm = true;
            findings.push(Finding::new(
                "high",
                "DESTRUCTIVE_RM",
                "Destructive root/home deletion command",
                format!("Contains destructive wipe command. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_cred && (lower.contains("~/.ssh") || lower.contains("/.ssh/id_") || lower.contains("/etc/shadow") || lower.contains("~/.aws/credentials")) {
            hit_cred = true;
            findings.push(Finding::new(
                "medium",
                "CREDENTIAL_ACCESS",
                "References sensitive credential paths",
                format!("Targets SSH keys, AWS credentials, or `/etc/shadow`. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_persist && (lower.contains("crontab") || lower.contains("systemctl enable") || lower.contains("/etc/cron.d/") || (lower.contains(">>") && (lower.contains(".bashrc") || lower.contains(".zshrc")))) {
            hit_persist = true;
            findings.push(Finding::new(
                "medium",
                "PERSISTENCE_HOOK",
                "Modifies startup or persistence mechanism",
                format!("References cron, systemd, or shell profile injection. Match: `{}`", line.trim().chars().take(85).collect::<String>()),
            ));
        }
        if !hit_eval && (contains_ci(line, "eval(") || contains_ci(line, "exec(")) {
            hit_eval = true;
            findings.push(Finding::new(
                "low",
                "DYNAMIC_EVAL",
                "Dynamic code evaluation (`eval`/`exec`)",
                "Uses dynamic code execution; review carefully if the source is untrusted.",
            ));
        }
    }

    if matches!(ext, ".sh" | ".bash" | ".zsh" | ".py" | ".js") && longest_line > 1200 {
        findings.push(Finding::new(
            "medium",
            "OBFUSCATED_LONG_LINE",
            format!("Extremely long single line ({} chars)", longest_line),
            "Scripts with very long single lines may hide obfuscated or encoded payloads.",
        ));
    }

    // Apply custom safety rule packs (community.rules + ~/.config/omarchy/omapeek.rules)
    let scan_lower = scan_text.to_ascii_lowercase();
    for rule in custom_rules {
        let ext_matches = rule.extensions.iter().any(|e| e == "*" || e == ext);
        if ext_matches && scan_lower.contains(&rule.needle_lower) {
            findings.push(Finding::new(&rule.severity, &rule.code, &rule.title, &rule.detail));
        }
    }

    let lang = ext.trim_start_matches('.');
    let lang = if !lang.is_empty() {
        lang
    } else if preview_text.starts_with("#!") {
        "sh"
    } else {
        "text"
    };

    Ok(format!(
        "{{\"language\":{},\"line_count\":{},\"truncated\":{},\"content\":{}}}",
        json_escape(lang),
        line_count,
        truncated,
        json_escape(&preview_text)
    ))
}

// ============================================================================
// Image Inspector (Header Dimensions + Polyglot / EXIF Checks)
// ============================================================================

fn parse_svg_attr(text: &str, attr: &str) -> Option<u64> {
    let needle = format!("{}=", attr);
    let pos = text.find(&needle)?;
    let rest = &text[pos + needle.len()..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &rest[1..];
    let num_str: String = inner.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    num_str.parse::<f64>().ok().map(|v| v as u64)
}

fn inspect_image(path: &Path, header: &[u8], magic: Option<&str>, findings: &mut Vec<Finding>) -> io::Result<String> {
    let mut width: Option<u64> = None;
    let mut height: Option<u64> = None;

    match magic {
        Some("png") if header.len() >= 24 => {
            width = Some(u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as u64);
            height = Some(u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as u64);
        }
        Some("gif") if header.len() >= 10 => {
            width = Some(u16::from_le_bytes([header[6], header[7]]) as u64);
            height = Some(u16::from_le_bytes([header[8], header[9]]) as u64);
        }
        Some("svg") => {
            let text = String::from_utf8_lossy(header);
            width = parse_svg_attr(&text, "width");
            height = parse_svg_attr(&text, "height");
        }
        Some("jpeg") => {
            // Stream-scan SOF marker in first 64 KB
            let mut f = File::open(path)?;
            let mut buf = Vec::new();
            f.by_ref().take(65536).read_to_end(&mut buf)?;
            let mut i = 2usize;
            while i + 4 < buf.len() {
                if buf[i] != 0xFF {
                    break;
                }
                while i < buf.len() && buf[i] == 0xFF {
                    i += 1;
                }
                if i >= buf.len() {
                    break;
                }
                let marker = buf[i];
                i += 1;
                if marker == 0xD8 || marker == 0xD9 {
                    continue;
                }
                if i + 2 > buf.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
                if matches!(marker, 0xC0 | 0xC1 | 0xC2) && i + 7 <= buf.len() {
                    height = Some(u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as u64);
                    width = Some(u16::from_be_bytes([buf[i + 5], buf[i + 6]]) as u64);
                    break;
                }
                i += seg_len.max(2);
            }
        }
        _ => {}
    }

    // Bounded EXIF & PNG polyglot scan (first 64KB + last 64KB)
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let mut head_chunk = Vec::new();
    f.by_ref().take(65536).read_to_end(&mut head_chunk)?;
    if find_bytes(&head_chunk, b"GPSInfo").is_some()
        || (find_bytes(&head_chunk, b"Exif\x00\x00").is_some() && find_bytes(&head_chunk, b"GPS").is_some())
    {
        findings.push(Finding::new(
            "info",
            "EXIF_GPS",
            "Image may contain EXIF/GPS metadata",
            "Consider stripping EXIF metadata before sharing publicly.",
        ));
    }

    if magic == Some("png") {
        let tail_start = len.saturating_sub(65536);
        f.seek(SeekFrom::Start(tail_start))?;
        let mut tail = Vec::new();
        f.read_to_end(&mut tail)?;
        if let Some(iend) = find_bytes(&tail, b"IEND") {
            if tail.len() > iend + 72 {
                let trailing = &tail[iend + 8..];
                if find_bytes(trailing, b"PK\x03\x04").is_some()
                    || find_bytes(trailing, b"#!/").is_some()
                    || find_bytes(trailing, b"<script").is_some()
                {
                    findings.push(Finding::new(
                        "high",
                        "POLYGLOT_IMAGE",
                        "Suspicious trailing payload after PNG end marker",
                        "Image contains embedded archive or script data appended after the PNG `IEND` chunk.",
                    ));
                }
            }
        }
    }

    let fmt = magic.unwrap_or("image");
    Ok(format!(
        "{{\"width\":{},\"height\":{},\"format\":{}}}",
        json_opt_u64(width),
        json_opt_u64(height),
        json_escape(fmt)
    ))
}

// ============================================================================
// Audio / Video Inspector (Native WAV + Optional ffprobe)
// ============================================================================

fn extract_ffprobe_field(json_str: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let pos = json_str.find(&needle)?;
    let rest = json_str[pos + needle.len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let val: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        if val.is_empty() { None } else { Some(val) }
    }
}

fn inspect_media(path: &Path, header: &[u8], magic: Option<&str>, media_kind: &str) -> String {
    let mut codec: Option<String> = magic.map(|m| m.to_ascii_uppercase());
    let mut duration_secs: Option<f64> = None;
    let mut sample_rate: Option<u64> = None;
    let mut channels: Option<u64> = None;
    let mut width: Option<u64> = None;
    let mut height: Option<u64> = None;
    let mut bitrate: Option<u64> = None;

    // Native WAV header parser (zero external tools needed)
    if magic == Some("wav") && header.len() >= 44 && &header[12..16] == b"fmt " {
        channels = Some(read_u16_le(header, 22) as u64);
        sample_rate = Some(read_u32_le(header, 24) as u64);
        let byte_rate = read_u32_le(header, 28) as f64;
        if let Ok(meta) = fs::metadata(path) {
            if byte_rate > 0.0 && meta.len() > 44 {
                duration_secs = Some((meta.len() - 44) as f64 / byte_rate);
            }
        }
        codec = Some("PCM/WAV".to_string());
    }

    // Optional ffprobe enrichment (if ffmpeg/ffprobe is installed)
    if let Ok(out) = Command::new("ffprobe")
        .args(["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            if let Some(c) = extract_ffprobe_field(&txt, "codec_name") {
                codec = Some(c.to_ascii_uppercase());
            }
            if let Some(d) = extract_ffprobe_field(&txt, "duration").and_then(|v| v.parse::<f64>().ok()) {
                duration_secs = Some(d);
            }
            if let Some(sr) = extract_ffprobe_field(&txt, "sample_rate").and_then(|v| v.parse::<u64>().ok()) {
                sample_rate = Some(sr);
            }
            if let Some(ch) = extract_ffprobe_field(&txt, "channels").and_then(|v| v.parse::<u64>().ok()) {
                channels = Some(ch);
            }
            if let Some(w) = extract_ffprobe_field(&txt, "width").and_then(|v| v.parse::<u64>().ok()) {
                width = Some(w);
            }
            if let Some(h) = extract_ffprobe_field(&txt, "height").and_then(|v| v.parse::<u64>().ok()) {
                height = Some(h);
            }
            if let Some(br) = extract_ffprobe_field(&txt, "bit_rate").and_then(|v| v.parse::<u64>().ok()) {
                bitrate = Some(br / 1000);
            }
        }
    }

    let dur_json = match duration_secs {
        Some(d) => format!("{:.2}", d),
        None => "null".to_string(),
    };

    format!(
        "{{\"media_kind\":{},\"codec\":{},\"duration_secs\":{},\"sample_rate\":{},\"channels\":{},\"width\":{},\"height\":{},\"bitrate_kbps\":{}}}",
        json_escape(media_kind),
        json_opt_str(&codec),
        dur_json,
        json_opt_u64(sample_rate),
        json_opt_u64(channels),
        json_opt_u64(width),
        json_opt_u64(height),
        json_opt_u64(bitrate),
    )
}

// ============================================================================
// Core Entrypoint
// ============================================================================

fn inspect_file(target: &str) -> io::Result<String> {
    let path = fs::canonicalize(target)?;
    let meta = fs::metadata(&path)?;
    if meta.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Path is a directory: {}", target)));
    }

    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default();
    let lower_name = name.to_ascii_lowercase();

    let mut f = File::open(&path)?;
    let mut header = [0u8; 4096];
    let n = f.read(&mut header)?;
    let header = &header[..n];

    let magic = detect_magic(header);
    let magic_tag = magic.map(|(t, _)| t);
    let magic_label = magic.map(|(_, l)| l).unwrap_or("Text / Unknown");
    let executable = (meta.permissions().mode() & 0o111) != 0;

    let mut findings: Vec<Finding> = Vec::new();
    check_general_safety(&name, &ext, magic, executable, &mut findings);

    let sha256 = sha256_file(&path)?;
    let sha_prefix = &sha256[..16];
    let custom_rules = load_custom_rules();

    let kind = if PDF_EXTS.contains(&ext.as_str()) || magic_tag == Some("pdf") {
        "pdf"
    } else if IMAGE_EXTS.contains(&ext.as_str()) {
        if matches!(magic_tag, Some("elf" | "macho" | "pe" | "shebang")) {
            if magic_tag == Some("shebang") { "code" } else { "binary" }
        } else {
            "image"
        }
    } else if AUDIO_EXTS.contains(&ext.as_str()) || matches!(magic_tag, Some("mp3" | "wav" | "flac" | "ogg" | "m4a")) {
        if matches!(magic_tag, Some("elf" | "macho" | "pe" | "shebang")) {
            if magic_tag == Some("shebang") { "code" } else { "binary" }
        } else {
            "audio"
        }
    } else if VIDEO_EXTS.contains(&ext.as_str()) || matches!(magic_tag, Some("mp4" | "mkv" | "avi")) {
        if matches!(magic_tag, Some("elf" | "macho" | "pe" | "shebang")) {
            if magic_tag == Some("shebang") { "code" } else { "binary" }
        } else {
            "video"
        }
    } else if matches!(magic_tag, Some("png" | "jpeg" | "gif" | "webp" | "svg")) {
        "image"
    } else if magic_tag == Some("zip")
        || ARCHIVE_EXTS.contains(&ext.as_str())
        || lower_name.ends_with(".tar.gz")
        || lower_name.ends_with(".tar.bz2")
        || lower_name.ends_with(".tar.xz")
    {
        "archive"
    } else if MARKDOWN_EXTS.contains(&ext.as_str()) {
        "markdown"
    } else if CODE_EXTS.contains(&ext.as_str()) || magic_tag == Some("shebang") || is_probably_text(header) {
        "code"
    } else {
        "binary"
    };

    let preview_json = match kind {
        "archive" => {
            if magic_tag == Some("zip") || matches!(ext.as_str(), ".zip" | ".whl" | ".jar") {
                inspect_zip_streaming(&path, &mut findings)?
            } else {
                inspect_tar_via_cli(&path, &mut findings)?
            }
        }
        "pdf" => inspect_pdf(&path, sha_prefix, &mut findings)?,
        "code" | "markdown" => inspect_code(&path, &ext, &custom_rules, &mut findings)?,
        "image" => inspect_image(&path, header, magic_tag, &mut findings)?,
        "audio" | "video" => inspect_media(&path, header, magic_tag, kind),
        _ => {
            let hex: Vec<String> = header.iter().take(64).map(|b| format!("{:02x}", b)).collect();
            format!(
                "{{\"hex_head\":{},\"magic_label\":{}}}",
                json_escape(&hex.join(" ")),
                json_escape(magic_label)
            )
        }
    };

    let modified_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Safety summary
    let score: u32 = findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "high" => 45,
            "medium" => 20,
            "low" => 8,
            _ => 0,
        })
        .sum::<u32>()
        .min(100);
    let high_count = findings.iter().filter(|f| f.severity == "high").count();
    let med_count = findings.iter().filter(|f| f.severity == "medium").count();

    let (verdict, summary) = if high_count > 0 || score >= 45 {
        ("danger", format!("{} high-risk indicator(s) found — inspect carefully before opening or extracting.", high_count))
    } else if med_count > 0 || score >= 15 {
        ("caution", format!("{} caution indicator(s) found — review details below.", med_count))
    } else {
        ("safe", "No static red flags detected (offline heuristic scan).".to_string())
    };

    let findings_json: Vec<String> = findings.iter().map(|f| f.to_json()).collect();

    Ok(format!(
        "{{\"meta\":{{\"name\":{},\"path\":{},\"extension\":{},\"size\":{},\"size_human\":{},\"mime\":{},\"magic\":{},\"executable\":{},\"modified\":{},\"sha256\":{}}},\"kind\":{},\"preview\":{},\"safety\":{{\"verdict\":{},\"score\":{},\"summary\":{},\"rules_loaded\":{},\"findings\":[{}]}}}}",
        json_escape(&name),
        json_escape(&path.to_string_lossy()),
        json_escape(&ext),
        meta.len(),
        json_escape(&human_size(meta.len())),
        json_escape(mime_for_ext(&ext)),
        json_escape(magic_label),
        executable,
        json_escape(&modified_secs.to_string()),
        json_escape(&sha256),
        json_escape(kind),
        preview_json,
        json_escape(verdict),
        score,
        json_escape(&summary),
        custom_rules.len(),
        findings_json.join(","),
    ))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{{\"error\":\"Usage: omapeek-inspect <file-path>\"}}");
        std::process::exit(1);
    }
    match inspect_file(&args[1]) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("{{\"error\":{}}}", json_escape(&e.to_string()));
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty_and_abc() {
        let h_empty = Sha256::new().finalize_hex();
        assert_eq!(h_empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(h.finalize_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_double_extension_detection() {
        assert_eq!(is_double_ext("invoice.pdf.sh"), Some(".pdf.sh".to_string()));
        assert_eq!(is_double_ext("archive.tar.gz"), None);
    }
}
