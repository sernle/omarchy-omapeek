#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine;
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_DATA_URI_BYTES: u64 = 15 * 1024 * 1024; // 15 MB

#[derive(Serialize)]
struct SampleItem {
    name: String,
    path: String,
}

fn find_repo_root() -> PathBuf {
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..8 {
            if let Some(dir) = cur {
                if dir.join("bin/omapeek-inspect").exists() || dir.join("samples").exists() {
                    return dir;
                }
                cur = dir.parent().map(|p| p.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        if cwd.join("bin/omapeek-inspect").exists() {
            return cwd;
        }
        if let Some(parent) = cwd.parent() {
            if parent.join("bin/omapeek-inspect").exists() {
                return parent.to_path_buf();
            }
        }
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn inspector_bin(root: &Path) -> PathBuf {
    let bin = root.join("bin/omapeek-inspect");
    if bin.exists() {
        return bin;
    }
    root.join("inspector-rs/target/release/omapeek-inspect")
}

#[tauri::command]
fn initial_file() -> Option<String> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let p = Path::new(&args[1]);
        if p.exists() {
            return Some(fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().to_string());
        }
    }
    None
}

#[tauri::command]
fn list_samples() -> Vec<SampleItem> {
    let root = find_repo_root();
    let samples_dir = root.join("samples");
    let mut items = Vec::new();
    if let Ok(entries) = fs::read_dir(&samples_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if !name.starts_with('.') {
                        items.push(SampleItem {
                            name: name.to_string(),
                            path: p.to_string_lossy().to_string(),
                        });
                    }
                }
            }
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

#[tauri::command]
fn inspect_file(path: String) -> Result<serde_json::Value, String> {
    let root = find_repo_root();
    let bin = inspector_bin(&root);
    let out = Command::new(&bin)
        .arg(&path)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", bin.display(), e))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            format!("Inspector exited with {}", out.status)
        } else {
            err
        });
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("Invalid JSON: {}", e))
}

#[tauri::command]
fn read_data_uri(path: String, mime: String) -> Result<String, String> {
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_DATA_URI_BYTES {
        return Err("File too large for inline preview (>15 MB)".to_string());
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Ok(format!("data:{};base64,{}", mime, b64))
}

#[tauri::command]
fn open_default(path: String) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(not(target_os = "macos"))]
    let cmd = "xdg-open";

    Command::new(cmd)
        .arg(&path)
        .spawn()
        .map_err(|e| format!("Failed to launch {}: {}", cmd, e))?;
    Ok("Opened with system default app".to_string())
}

#[tauri::command]
fn sandbox_open(path: String) -> Result<String, String> {
    let root = find_repo_root();
    let script = root.join("bin/omapeek-quarantine");
    let out = Command::new(&script)
        .args(["open", &path])
        .output()
        .map_err(|e| format!("Failed to run quarantine helper: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() { "Sandbox open failed".into() } else { err });
    }
    Ok("Opened in isolated sandbox".to_string())
}

#[tauri::command]
fn quarantine_file(path: String) -> Result<String, String> {
    let root = find_repo_root();
    let script = root.join("bin/omapeek-quarantine");
    let out = Command::new(&script)
        .args(["vault", &path])
        .output()
        .map_err(|e| format!("Failed to run quarantine helper: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() { "Quarantine failed".into() } else { err });
    }
    let dest = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(dest)
}

fn main() {
    #[cfg(target_os = "linux")]
    if env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        // Avoid blank WebKitGTK window under Wayland / Hyprland virtualized GPUs
        unsafe { env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1"); }
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            initial_file,
            list_samples,
            inspect_file,
            read_data_uri,
            open_default,
            sandbox_open,
            quarantine_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OmaPeek Tauri application");
}
