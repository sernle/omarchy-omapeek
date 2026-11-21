#!/usr/bin/env python3
"""
OmaPeek Inspector & Offline Static Safety Analyzer.
Zero external dependencies (Python 3 stdlib only). Works on Arch Linux (Omarchy) and macOS.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import stat
import struct
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_TEXT_BYTES = 128 * 1024  # 128 KB preview cap
MAX_ARCHIVE_ENTRIES = 500
ZIP_BOMB_RATIO = 100.0
ZIP_BOMB_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico", ".avif"}
MARKDOWN_EXTS = {".md", ".markdown", ".mdx"}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".whl", ".jar"}
PDF_EXTS = {".pdf"}
CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".qml", ".sh", ".bash", ".zsh", ".fish",
    ".rs", ".go", ".c", ".h", ".cpp", ".hpp", ".java", ".kt", ".swift", ".rb",
    ".php", ".lua", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".xml", ".html", ".htm", ".css", ".scss", ".sql", ".dockerfile", ".env",
    ".txt", ".log", ".csv", ".gitignore", ".nix", ".vim",
}
EXECUTABLE_EXTS = {
    ".sh", ".bash", ".zsh", ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".msi", ".appimage", ".run", ".bin", ".elf", ".dmg", ".pkg", ".command",
    ".scr", ".com", ".jar", ".deb", ".rpm",
}

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
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
    (b"RIFF", "riff", "RIFF/WebP container"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"PK\x05\x06", "zip", "Empty ZIP archive"),
    (b"\x1f\x8b", "gzip", "GZIP archive"),
    (b"BZh", "bzip2", "BZIP2 archive"),
    (b"\xfd7zXZ\x00", "xz", "XZ archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"#!", "shebang", "Executable script (shebang)"),
]

CODE_SUSPICIOUS_RULES: list[tuple[str, str, str, str, re.Pattern[str]]] = [
    (
        "high",
        "PIPE_TO_SHELL",
        "Remote download piped directly to shell",
        "Pattern like `curl/wget ... | sh/bash` executes remote untrusted code immediately.",
        re.compile(r"(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.IGNORECASE),
    ),
    (
        "high",
        "BASE64_EXEC",
        "Obfuscated Base64 payload execution",
        "Decodes base64 content directly into a shell or eval interpreter.",
        re.compile(r"base64\s+(-d|--decode)[^\n|]{0,120}\|\s*(ba|z|da)?sh\b|eval\s+[\"\']?\$\(", re.IGNORECASE),
    ),
    (
        "high",
        "REVERSE_SHELL",
        "Reverse shell pattern detected",
        "Contains classic interactive network shell redirection (`/dev/tcp`, `nc -e`, or `bash -i`).",
        re.compile(r"/dev/tcp/|bash\s+-i\s+>&|\bnc\b[^\n]{0,60}\s-e\s|\bmkfifo\b[^\n]{0,80}\bnc\b", re.IGNORECASE),
    ),
    (
        "high",
        "DESTRUCTIVE_RM",
        "Destructive root filesystem deletion",
        "Contains `rm -rf /` or similar destructive wipe command.",
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(/|~|\$HOME)(\s|$)", re.IGNORECASE),
    ),
    (
        "medium",
        "CREDENTIAL_ACCESS",
        "References sensitive credential paths",
        "Reads or targets SSH keys, AWS credentials, `/etc/shadow`, or browser keychains.",
        re.compile(r"(~/.ssh|/\.ssh/id_|/etc/shadow|~/.aws/credentials|keychain|Login Data)", re.IGNORECASE),
    ),
    (
        "medium",
        "PERSISTENCE_HOOK",
        "Modifies startup or persistence mechanism",
        "References `crontab`, `systemctl enable`, `/etc/rc.local`, or shell profile injection.",
        re.compile(r"(\bcrontab\b|systemctl\s+enable|>>\s*~/?\.(bashrc|zshrc|profile)|/etc/cron\.d/)", re.IGNORECASE),
    ),
    (
        "low",
        "DYNAMIC_EVAL",
        "Dynamic code evaluation (`eval`/`exec`)",
        "Uses dynamic code execution; review carefully if the source is untrusted.",
        re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
    ),
]


def human_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{num_bytes} B"


def detect_magic(header: bytes) -> tuple[str | None, str | None]:
    for sig, tag, label in MAGIC_SIGNATURES:
        if header.startswith(sig):
            if tag == "riff" and len(header) >= 12 and header[8:12] == b"WEBP":
                return "webp", "WebP image"
            return tag, label
    stripped = header.lstrip()
    if stripped.startswith(b"<svg") or (stripped.startswith(b"<?xml") and b"<svg" in header[:512]):
        return "svg", "SVG vector image"
    return None, None


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def parse_image_dimensions(path: Path, header: bytes, magic: str | None) -> dict[str, Any]:
    info: dict[str, Any] = {"width": None, "height": None, "format": magic or path.suffix.lstrip(".").lower()}
    try:
        if magic == "png" and len(header) >= 24:
            w, h = struct.unpack(">II", header[16:24])
            info["width"], info["height"] = w, h
        elif magic == "gif" and len(header) >= 10:
            w, h = struct.unpack("<HH", header[6:10])
            info["width"], info["height"] = w, h
        elif magic == "jpeg":
            with path.open("rb") as f:
                f.seek(2)
                while True:
                    marker = f.read(2)
                    if len(marker) < 2:
                        break
                    while marker[0] == 0xFF and marker[1] == 0xFF:
                        marker = b"\xff" + f.read(1)
                    if marker[0] != 0xFF:
                        break
                    code = marker[1]
                    if code in (0xD8, 0xD9):
                        continue
                    length_bytes = f.read(2)
                    if len(length_bytes) < 2:
                        break
                    seg_len = struct.unpack(">H", length_bytes)[0]
                    if code in (0xC0, 0xC1, 0xC2):
                        sof = f.read(5)
                        if len(sof) == 5:
                            h, w = struct.unpack(">HH", sof[1:5])
                            info["width"], info["height"] = w, h
                        break
                    f.seek(max(0, seg_len - 2), os.SEEK_CUR)
        elif magic == "svg":
            text = header.decode("utf-8", errors="ignore")
            w_m = re.search(r'\bwidth=["\']([0-9.]+)', text)
            h_m = re.search(r'\bheight=["\']([0-9.]+)', text)
            if w_m and h_m:
                info["width"], info["height"] = int(float(w_m.group(1))), int(float(h_m.group(1)))
    except Exception:
        pass
    return info


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def classify_file(path: Path, ext: str, magic: str | None, header: bytes) -> str:
    lower_name = path.name.lower()
    if ext in PDF_EXTS or magic == "pdf":
        return "pdf"
    if ext in IMAGE_EXTS:
        # Only treat as image if magic doesn't contradict it (spoofed images still show warning)
        if magic in {"elf", "macho", "pe", "shebang"}:
            return "code" if magic == "shebang" else "binary"
        return "image"
    if magic in {"png", "jpeg", "gif", "webp", "svg"}:
        return "image"
    if ext in ARCHIVE_EXTS or lower_name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")) or magic in {"zip", "gzip", "bzip2", "xz"}:
        if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
            return "archive"
    if ext in MARKDOWN_EXTS:
        return "markdown"
    if ext in CODE_EXTS or magic == "shebang" or is_probably_text(header):
        return "code"
    return "binary"


def add_finding(findings: list[dict[str, str]], severity: str, code: str, title: str, detail: str) -> None:
    findings.append({
        "severity": severity,
        "code": code,
        "title": title,
        "detail": detail,
    })


def check_general_safety(path: Path, ext: str, magic: str | None, magic_label: str | None, st: os.stat_result, findings: list[dict[str, str]]) -> None:
    name = path.name
    # 1. Right-to-Left Override Unicode spoofing
    if any(ch in name for ch in ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069")):
        add_finding(
            findings,
            "high",
            "RLO_SPOOF",
            "Unicode bidi override in filename",
            "Filename contains invisible Right-to-Left Override characters commonly used to disguise executable extensions.",
        )

    # 2. Double extension (e.g., invoice.pdf.sh)
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in (IMAGE_EXTS | PDF_EXTS | {".doc", ".docx", ".xls", ".txt"}):
        add_finding(
            findings,
            "high",
            "DOUBLE_EXTENSION",
            f"Suspicious double extension ({''.join(suffixes[-2:])})",
            f"File pretends to be `{suffixes[-2]}` but actually ends in executable extension `{suffixes[-1]}`.",
        )

    # 3. Magic-byte vs extension spoofing
    if ext in IMAGE_EXTS and magic in {"elf", "macho", "pe", "shebang", "zip", "pdf"}:
        add_finding(
            findings,
            "high",
            "EXTENSION_SPOOF",
            f"Disguised file: `{ext}` is actually {magic_label}",
            f"File extension claims to be an image (`{ext}`), but its header bytes match {magic_label}.",
        )
    elif ext in PDF_EXTS and magic in {"elf", "macho", "pe", "shebang", "zip"}:
        add_finding(
            findings,
            "high",
            "EXTENSION_SPOOF",
            f"Disguised file: `.pdf` is actually {magic_label}",
            f"File claims to be a PDF, but its header bytes match {magic_label}.",
        )

    # 4. Executable bit set on passive document/image
    is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    if is_exec and ext in (IMAGE_EXTS | PDF_EXTS | MARKDOWN_EXTS):
        add_finding(
            findings,
            "medium",
            "UNEXPECTED_EXEC_BIT",
            "Executable permission bit is set",
            f"Passive file type (`{ext}`) has Unix execute permissions (`+x`).",
        )


def inspect_archive(path: Path, findings: list[dict[str, str]]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    total_compressed = 0
    total_uncompressed = 0
    zip_slip_hits: list[str] = []
    exec_hits: list[str] = []
    double_ext_hits: list[str] = []
    symlink_hits: list[str] = []
    encrypted_count = 0

    if zipfile.is_zipfile(path):
        archive_type = "zip"
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            total_count = len(infos)
            for zi in infos:
                total_compressed += zi.compress_size
                total_uncompressed += zi.file_size
                flags: list[str] = []
                norm = zi.filename.replace("\\", "/")
                if norm.startswith("/") or ".." in Path(norm).parts:
                    zip_slip_hits.append(zi.filename)
                    flags.append("zip-slip")
                if zi.flag_bits & 0x1:
                    encrypted_count += 1
                    flags.append("encrypted")
                # Check Unix symlink mode in external_attr
                unix_mode = zi.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    symlink_hits.append(zi.filename)
                    flags.append("symlink")
                p = Path(norm)
                ext = p.suffix.lower()
                if not zi.is_dir() and ext in EXECUTABLE_EXTS:
                    exec_hits.append(zi.filename)
                    flags.append("executable")
                suffixes = [s.lower() for s in p.suffixes]
                if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in (IMAGE_EXTS | PDF_EXTS | {".doc", ".docx", ".txt"}):
                    double_ext_hits.append(zi.filename)
                    flags.append("double-ext")
                if len(entries) < MAX_ARCHIVE_ENTRIES:
                    entries.append({
                        "name": zi.filename,
                        "is_dir": zi.is_dir(),
                        "size": zi.file_size,
                        "compressed_size": zi.compress_size,
                        "flags": flags,
                    })
    else:
        archive_type = "tar"
        with tarfile.open(path, "r:*") as tf:
            members = tf.getmembers()
            total_count = len(members)
            total_compressed = path.stat().st_size
            for m in members:
                total_uncompressed += m.size
                flags = []
                norm = m.name.replace("\\", "/")
                if norm.startswith("/") or ".." in Path(norm).parts:
                    zip_slip_hits.append(m.name)
                    flags.append("zip-slip")
                if m.issym() or m.islnk():
                    symlink_hits.append(f"{m.name} -> {m.linkname}")
                    flags.append("symlink")
                p = Path(norm)
                ext = p.suffix.lower()
                if m.isfile() and ext in EXECUTABLE_EXTS:
                    exec_hits.append(m.name)
                    flags.append("executable")
                if len(entries) < MAX_ARCHIVE_ENTRIES:
                    entries.append({
                        "name": m.name,
                        "is_dir": m.isdir(),
                        "size": m.size,
                        "compressed_size": None,
                        "flags": flags,
                    })

    ratio = (total_uncompressed / total_compressed) if total_compressed > 0 else 1.0

    if zip_slip_hits:
        add_finding(
            findings,
            "high",
            "ZIP_SLIP",
            f"Path traversal (Zip-Slip) in {len(zip_slip_hits)} entr{'y' if len(zip_slip_hits) == 1 else 'ies'}",
            f"Archive writes outside target directory: {', '.join(zip_slip_hits[:3])}",
        )
    if ratio >= ZIP_BOMB_RATIO or total_uncompressed >= ZIP_BOMB_UNCOMPRESSED_BYTES:
        add_finding(
            findings,
            "high",
            "ZIP_BOMB",
            f"Possible zip bomb ({ratio:.0f}x ratio, {human_size(total_uncompressed)} unpacked)",
            "Extreme compression ratio or uncompressed size could exhaust disk space on extraction.",
        )
    if double_ext_hits:
        add_finding(
            findings,
            "high",
            "ARCHIVE_DOUBLE_EXT",
            f"Disguised double-extension file inside archive",
            f"Suspicious entry: {', '.join(double_ext_hits[:3])}",
        )
    if exec_hits:
        add_finding(
            findings,
            "medium",
            "ARCHIVE_EXECUTABLES",
            f"Contains {len(exec_hits)} executable/script file(s)",
            f"Inspect before running: {', '.join(exec_hits[:4])}",
        )
    if symlink_hits:
        add_finding(
            findings,
            "medium",
            "ARCHIVE_SYMLINKS",
            f"Contains {len(symlink_hits)} symlink(s)",
            f"Symlinks can point outside the extraction directory: {', '.join(symlink_hits[:3])}",
        )
    if encrypted_count:
        add_finding(
            findings,
            "low",
            "ARCHIVE_ENCRYPTED",
            f"{encrypted_count} password-protected entr{'y' if encrypted_count == 1 else 'ies'}",
            "Encrypted archive contents cannot be statically scanned before extraction.",
        )

    return {
        "archive_type": archive_type,
        "entry_count": total_count,
        "truncated": total_count > MAX_ARCHIVE_ENTRIES,
        "total_uncompressed": total_uncompressed,
        "total_uncompressed_human": human_size(total_uncompressed),
        "compression_ratio": round(ratio, 2),
        "entries": entries,
    }


def inspect_pdf(path: Path, findings: list[dict[str, str]]) -> dict[str, Any]:
    raw = path.read_bytes()
    header_line = raw[:32].decode("latin-1", errors="ignore").splitlines()[0] if raw else ""
    version_match = re.search(r"%PDF-(\d+\.\d+)", header_line)
    version = version_match.group(1) if version_match else "unknown"

    # Approximate page count from /Type /Page tokens
    page_matches = re.findall(rb"/Type\s*/Page\b(?!s)", raw)
    page_count = max(1, len(page_matches)) if raw.startswith(b"%PDF-") else 0

    # Security scans on raw PDF tokens
    pdf_checks = [
        ("high", "PDF_JAVASCRIPT", rb"/JavaScript\b|/JS\b", "Embedded JavaScript in PDF", "PDF contains `/JavaScript` or `/JS` actions that can execute scripts in vulnerable readers."),
        ("high", "PDF_LAUNCH", rb"/Launch\b", "External command `/Launch` action", "PDF attempts to launch an external program or file."),
        ("medium", "PDF_OPENACTION", rb"/OpenAction\b|/AA\b", "Auto-execute action on open (`/OpenAction`)", "PDF defines an automatic action triggered immediately when opened."),
        ("medium", "PDF_EMBEDDED_FILE", rb"/EmbeddedFile\b", "Contains embedded file attachment", "PDF embeds another file inside its object stream."),
        ("low", "PDF_EXTERNAL_URI", rb"/URI\b|/SubmitForm\b", "External URLs or form submission", "PDF references external links (`/URI`) or remote form submission (`/SubmitForm`)."),
    ]
    for sev, code, pattern, title, detail in pdf_checks:
        if re.search(pattern, raw):
            add_finding(findings, sev, code, title, detail)

    # Extract readable title if present
    title_m = re.search(rb"/Title\s*\(([^)]{1,120})\)", raw)
    title = title_m.group(1).decode("latin-1", errors="ignore") if title_m else None

    return {
        "version": version,
        "page_count": page_count,
        "title": title,
    }


def inspect_code(path: Path, ext: str, findings: list[dict[str, str]]) -> dict[str, Any]:
    raw = path.read_bytes()
    truncated = len(raw) > MAX_TEXT_BYTES
    text = raw[:MAX_TEXT_BYTES].decode("utf-8", errors="replace")
    lines = text.splitlines()

    # Scan full file (up to 1 MB) for suspicious patterns
    scan_text = raw[: 1024 * 1024].decode("utf-8", errors="ignore")
    for sev, code, title, detail, pattern in CODE_SUSPICIOUS_RULES:
        m = pattern.search(scan_text)
        if m:
            snippet = m.group(0).strip().replace("\n", " ")[:90]
            add_finding(findings, sev, code, title, f"{detail} Match: `{snippet}`")

    # Detect very long obfuscated lines (e.g., minified/base64 blobs in shell scripts)
    if ext in {".sh", ".bash", ".zsh", ".py", ".js"}:
        longest = max((len(line) for line in lines), default=0)
        if longest > 1200:
            add_finding(
                findings,
                "medium",
                "OBFUSCATED_LONG_LINE",
                f"Extremely long single line ({longest} chars)",
                "Scripts with very long single lines may hide obfuscated or encoded payloads.",
            )

    lang = ext.lstrip(".") or ("sh" if text.startswith("#!") else "text")
    return {
        "language": lang,
        "line_count": len(lines),
        "truncated": truncated,
        "content": text,
    }


def inspect_image(path: Path, header: bytes, magic: str | None, findings: list[dict[str, str]]) -> dict[str, Any]:
    dims = parse_image_dimensions(path, header, magic)
    raw = path.read_bytes()

    # Check for EXIF GPS privacy metadata
    if b"GPSInfo" in raw or (b"Exif\x00\x00" in raw and b"GPS" in raw[:65536]):
        add_finding(
            findings,
            "info",
            "EXIF_GPS",
            "Image may contain EXIF/GPS metadata",
            "Consider stripping EXIF metadata before sharing publicly.",
        )

    # Polyglot check: embedded archive or script markers after PNG IEND / JPEG EOI
    if magic == "png":
        iend = raw.find(b"IEND")
        if iend != -1 and len(raw) - (iend + 8) > 64:
            trailing = raw[iend + 8 :]
            if b"PK\x03\x04" in trailing or b"#!/" in trailing or b"<script" in trailing.lower():
                add_finding(
                    findings,
                    "high",
                    "POLYGLOT_IMAGE",
                    "Suspicious trailing payload after PNG end marker",
                    "Image contains embedded archive or script data appended after the PNG `IEND` chunk.",
                )

    return dims


def summarize_safety(findings: list[dict[str, str]]) -> dict[str, Any]:
    weights = {"high": 45, "medium": 20, "low": 8, "info": 0}
    score = min(100, sum(weights.get(f["severity"], 0) for f in findings))
    high_count = sum(1 for f in findings if f["severity"] == "high")
    med_count = sum(1 for f in findings if f["severity"] == "medium")

    if high_count > 0 or score >= 45:
        verdict = "danger"
        summary = f"{high_count} high-risk indicator(s) found — inspect carefully before opening or extracting."
    elif med_count > 0 or score >= 15:
        verdict = "caution"
        summary = f"{med_count} caution indicator(s) found — review details below."
    else:
        verdict = "safe"
        summary = "No static red flags detected (offline heuristic scan)."

    return {
        "verdict": verdict,
        "score": score,
        "summary": summary,
        "findings": findings,
    }


def inspect_file(target: str) -> dict[str, Any]:
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {target}")
    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory: {target}")

    st = path.stat()
    ext = path.suffix.lower()
    with path.open("rb") as f:
        header = f.read(4096)

    magic, magic_label = detect_magic(header)
    kind = classify_file(path, ext, magic, header)
    mime, _ = mimetypes.guess_type(str(path))
    findings: list[dict[str, str]] = []

    check_general_safety(path, ext, magic, magic_label, st, findings)

    preview: dict[str, Any] = {}
    if kind == "archive":
        preview = inspect_archive(path, findings)
    elif kind == "pdf":
        preview = inspect_pdf(path, findings)
    elif kind in {"code", "markdown"}:
        preview = inspect_code(path, ext, findings)
    elif kind == "image":
        preview = inspect_image(path, header, magic, findings)
    else:
        preview = {
            "hex_head": header[:64].hex(" "),
            "magic_label": magic_label or "Unknown binary data",
        }

    return {
        "meta": {
            "name": path.name,
            "path": str(path),
            "extension": ext,
            "size": st.st_size,
            "size_human": human_size(st.st_size),
            "mime": mime or "application/octet-stream",
            "magic": magic_label or "Text / Unknown",
            "executable": bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
            "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "sha256": compute_sha256(path),
        },
        "kind": kind,
        "preview": preview,
        "safety": summarize_safety(findings),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: omapeek-inspect.py <file-path>"}), file=sys.stderr)
        return 1
    try:
        result = inspect_file(sys.argv[1])
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
