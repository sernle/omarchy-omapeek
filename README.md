# OmaPeek — Quick Look + Offline Safety Shield for Omarchy

Brings macOS-style instant **Quick Look** (`Space` preview) to **Omarchy 4 (Quattro)**—paired with a 100% offline static safety analyzer so you can spot malicious archives, spoofed files, sketchy scripts, and weaponized PDFs *before* you open or extract them.

## Features
- **Instant Previews:** Images (PNG/JPEG/GIF/WebP/SVG), Markdown, Code/JSON/YAML, Archives (`.zip`, `.tar.*`), PDFs (with Page-1 thumbnail via `pdftoppm`/`qlmanage`), and Audio/Video metadata + playback (native WAV + optional `ffprobe`).
- **Offline Safety Shield (`SAFE` / `CAUTION` / `DANGER`):**
  - **Archives & ZIPs:** Zip-Slip path traversal (`../` or `/`), Zip-Bomb ratio/size checks, hidden executables, double extensions (`invoice.pdf.sh`), symlinks, encrypted entries.
  - **Scripts & Code:** `curl | bash` pipe-to-shell, Base64/eval obfuscation, reverse shells, destructive `rm -rf /`, credential path targeting (`~/.ssh`, `/etc/shadow`), persistence hooks (`crontab`).
  - **PDFs:** `/JavaScript` / `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/SubmitForm`.
  - **Spoofing & Privacy:** Magic-byte vs. extension mismatch (e.g., script disguised as `.png`/`.mp4`), Unicode Right-to-Left Override (`U+202E`), PNG polyglot payloads, EXIF GPS warnings, SHA-256 copy.
  - **Custom Rule Packs:** Ships with `rules/community.rules` (Discord/Telegram webhook exfil, `/etc/ld.so.preload`, cryptominers, `authorized_keys`, `curl -k`) and automatically loads user rules from `~/.config/omarchy/omapeek.rules` or `OMAPEEK_RULES`.

## Build the Native Rust Inspector (Zero Crates / Fast & Low Memory)
```bash
cd inspector-rs && cargo build --release && cp target/release/omapeek-inspect ../bin/omapeek-inspect
```
- **Zero external crate dependencies** (pure Rust `std`) — compiles offline in ~2s, ~460 KB stripped binary.
- **Streaming / bounded memory** — reads ZIP Central Directories directly from the tail without decompressing, streams SHA-256 in 64 KB chunks, and bounds PDF/code scans to 1 MB.

## Try it on macOS right now (Mock Runner)
```bash
python3 mock-runner/server.py
```
Then open `http://127.0.0.1:4173` in your browser, or run:
```bash
./bin/omapeek samples/evil_zipslip.zip
```

## Install on Omarchy Linux (Quattro)
Using the installer script (downloads prebuilt binary if `OMAPEEK_REPO` is set, builds with Cargo if installed, or falls back to Python 3):
```bash
./install.sh
```
Or package on Arch Linux with `packaging/PKGBUILD`:
```bash
cd packaging && makepkg -si
```
Prebuilt binaries for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin` are automatically built and published on `v*` tags via `.github/workflows/release.yml`.

Optional Hyprland keybind (`~/.config/hypr/bindings.conf`):
```ini
bind = SUPER, Space, exec, ~/.config/omarchy/plugins/sonlc.omapeek/bin/omapeek "$(wl-paste -n)"
```

## Run Tests
```bash
python3 -m unittest discover -s tests -v
```
