#!/usr/bin/env python3
"""Integration tests verifying the Rust `bin/omapeek-inspect` binary (and parity with Python fallback)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
RUST_BIN = ROOT / "bin" / "omapeek-inspect"

_spec = importlib.util.spec_from_file_location("omapeek_inspect", ROOT / "bin" / "omapeek-inspect.py")
assert _spec and _spec.loader
py_inspector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(py_inspector)


def inspect_rust(path: Path) -> dict:
    proc = subprocess.run([str(RUST_BIN), str(path)], capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


class TestOmaPeekRustInspector(unittest.TestCase):
    def test_safe_markdown(self) -> None:
        res = inspect_rust(SAMPLES / "notes.md")
        self.assertEqual(res["kind"], "markdown")
        self.assertEqual(res["safety"]["verdict"], "safe")

    def test_safe_code(self) -> None:
        res = inspect_rust(SAMPLES / "clean_script.py")
        self.assertEqual(res["kind"], "code")
        self.assertEqual(res["safety"]["verdict"], "safe")

    def test_safe_svg_image(self) -> None:
        res = inspect_rust(SAMPLES / "omarchy_badge.svg")
        self.assertEqual(res["kind"], "image")
        self.assertEqual(res["preview"]["width"], 420)
        self.assertEqual(res["preview"]["height"], 160)
        self.assertEqual(res["safety"]["verdict"], "safe")

    def test_safe_zip(self) -> None:
        res = inspect_rust(SAMPLES / "safe_archive.zip")
        self.assertEqual(res["kind"], "archive")
        self.assertEqual(res["preview"]["entry_count"], 3)
        self.assertEqual(res["safety"]["verdict"], "safe")

    def test_suspicious_script(self) -> None:
        res = inspect_rust(SAMPLES / "suspicious_script.sh")
        self.assertEqual(res["kind"], "code")
        self.assertEqual(res["safety"]["verdict"], "danger")
        codes = {f["code"] for f in res["safety"]["findings"]}
        self.assertIn("PIPE_TO_SHELL", codes)
        self.assertIn("CREDENTIAL_ACCESS", codes)

    def test_evil_zipslip(self) -> None:
        res = inspect_rust(SAMPLES / "evil_zipslip.zip")
        self.assertEqual(res["kind"], "archive")
        self.assertEqual(res["safety"]["verdict"], "danger")
        codes = {f["code"] for f in res["safety"]["findings"]}
        self.assertIn("ZIP_SLIP", codes)
        self.assertIn("ARCHIVE_DOUBLE_EXT", codes)

    def test_spoofed_image(self) -> None:
        res = inspect_rust(SAMPLES / "spoofed_image.png")
        self.assertEqual(res["safety"]["verdict"], "danger")
        codes = {f["code"] for f in res["safety"]["findings"]}
        self.assertIn("EXTENSION_SPOOF", codes)

    def test_suspicious_pdf(self) -> None:
        res = inspect_rust(SAMPLES / "suspicious_doc.pdf")
        self.assertEqual(res["kind"], "pdf")
        self.assertEqual(res["safety"]["verdict"], "danger")
        self.assertIn("thumbnail", res["preview"])
        codes = {f["code"] for f in res["safety"]["findings"]}
        self.assertIn("PDF_JAVASCRIPT", codes)
        self.assertIn("PDF_OPENACTION", codes)
        self.assertIn("PDF_LAUNCH", codes)

    def test_audio_wav_metadata(self) -> None:
        res = inspect_rust(SAMPLES / "chime.wav")
        self.assertEqual(res["kind"], "audio")
        self.assertEqual(res["safety"]["verdict"], "safe")
        self.assertEqual(res["preview"]["sample_rate"], 44100)
        self.assertEqual(res["preview"]["channels"], 1)
        self.assertGreater(res["preview"]["duration_secs"], 0.25)

    def test_custom_rule_pack_webhook(self) -> None:
        res = inspect_rust(SAMPLES / "webhook_stealer.py")
        self.assertEqual(res["kind"], "code")
        self.assertEqual(res["safety"]["verdict"], "danger")
        self.assertGreaterEqual(res["safety"]["rules_loaded"], 1)
        codes = {f["code"] for f in res["safety"]["findings"]}
        self.assertIn("WEBHOOK_EXFIL", codes)

    def test_rust_python_parity_core_samples(self) -> None:
        core = [
            "notes.md", "clean_script.py", "omarchy_badge.svg",
            "safe_archive.zip", "suspicious_script.sh", "evil_zipslip.zip",
            "spoofed_image.png", "suspicious_doc.pdf",
        ]
        for name in core:
            sample = SAMPLES / name
            rs = inspect_rust(sample)
            py = py_inspector.inspect_file(str(sample))
            self.assertEqual(rs["meta"]["sha256"], py["meta"]["sha256"], name)
            self.assertEqual(rs["kind"], py["kind"], name)
            self.assertEqual(rs["safety"]["verdict"], py["safety"]["verdict"], name)


if __name__ == "__main__":
    unittest.main()
