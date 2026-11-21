#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ID="sonlc.omapeek"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${OMAPEEK_INSTALL_DIR:-$HOME/.config/omarchy/plugins/$PLUGIN_ID}"
REPO="${OMAPEEK_REPO:-}"
ARCH="$(uname -m)"
OS="$(uname -s)"

echo "==> Installing OmaPeek ($PLUGIN_ID) to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/rules" "$INSTALL_DIR/mock-runner" "$INSTALL_DIR/samples"

cp "$SCRIPT_DIR/manifest.json" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/Overlay.qml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/BarWidget.qml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/bin/omapeek" "$INSTALL_DIR/bin/"
cp "$SCRIPT_DIR/bin/omapeek-inspect.py" "$INSTALL_DIR/bin/"
cp -r "$SCRIPT_DIR/rules/." "$INSTALL_DIR/rules/"
cp -r "$SCRIPT_DIR/mock-runner/." "$INSTALL_DIR/mock-runner/"
cp -r "$SCRIPT_DIR/samples/." "$INSTALL_DIR/samples/"
chmod +x "$INSTALL_DIR/bin/omapeek" "$INSTALL_DIR/bin/omapeek-inspect.py" "$INSTALL_DIR/mock-runner/server.py"

# 1. Try prebuilt binary in repo if matching host OS/arch
if [[ -x "$SCRIPT_DIR/bin/omapeek-inspect" ]] && file "$SCRIPT_DIR/bin/omapeek-inspect" | grep -qi "$OS"; then
  echo "==> Copying local native binary"
  cp "$SCRIPT_DIR/bin/omapeek-inspect" "$INSTALL_DIR/bin/omapeek-inspect"
  chmod +x "$INSTALL_DIR/bin/omapeek-inspect"

# 2. Try downloading prebuilt Linux binary from GitHub Releases if OMAPEEK_REPO is set
elif [[ -n "$REPO" && "$OS" == "Linux" ]]; then
  case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
    *) TARGET="" ;;
  esac
  if [[ -n "$TARGET" ]] && command -v curl >/dev/null 2>&1; then
    URL="https://github.com/${REPO}/releases/latest/download/omapeek-inspect-${TARGET}.tar.gz"
    echo "==> Downloading prebuilt Rust binary from $URL"
    if curl -fsSL "$URL" | tar -xz -C "$INSTALL_DIR/bin"; then
      chmod +x "$INSTALL_DIR/bin/omapeek-inspect"
    else
      echo "WARN: Prebuilt download failed; will try local Rust build or Python fallback."
    fi
  fi
fi

# 3. Build locally with Cargo if binary still missing and cargo is available
if [[ ! -x "$INSTALL_DIR/bin/omapeek-inspect" ]] && command -v cargo >/dev/null 2>&1; then
  echo "==> Building zero-dependency Rust binary with cargo..."
  (cd "$SCRIPT_DIR/inspector-rs" && cargo build --release)
  cp "$SCRIPT_DIR/inspector-rs/target/release/omapeek-inspect" "$INSTALL_DIR/bin/omapeek-inspect"
  chmod +x "$INSTALL_DIR/bin/omapeek-inspect"
fi

if [[ -x "$INSTALL_DIR/bin/omapeek-inspect" ]]; then
  echo "==> Native Rust inspector ready: $INSTALL_DIR/bin/omapeek-inspect"
else
  echo "==> Using Python 3 fallback inspector (install Rust to compile native binary)."
fi

# 4. Symlink CLI into ~/.local/bin if present
if [[ -d "$HOME/.local/bin" ]]; then
  ln -sf "$INSTALL_DIR/bin/omapeek" "$HOME/.local/bin/omapeek"
  echo "==> Linked CLI: $HOME/.local/bin/omapeek"
fi

# 5. Validate & reload on Omarchy Quattro
if command -v omarchy >/dev/null 2>&1; then
  omarchy plugin validate "$INSTALL_DIR" || true
fi
if command -v omarchy-shell >/dev/null 2>&1; then
  omarchy-shell shell rescanPlugins || true
fi

cat <<'EOF'

Done! Optional Hyprland keybind (~/.config/hypr/bindings.conf):
  bind = SUPER, Space, exec, ~/.config/omarchy/plugins/sonlc.omapeek/bin/omapeek "$(wl-paste -n)"

EOF
