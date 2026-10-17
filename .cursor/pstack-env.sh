#!/usr/bin/env bash
# pstack cloud-agent setup. Idempotent: safe in both `install` (every Build) and `start` (every agent run).
# Puts bun on the default PATH (exported PATH does not survive a Build snapshot) and installs the poteto-mode script deps.
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.bun/bin:$PATH"
if ! command -v bun >/dev/null 2>&1; then
  curl -fsSL https://bun.sh/install | bash || { echo "pstack-env: bun install failed" >&2; exit 0; }
fi
if [ -x "$HOME/.bun/bin/bun" ] && ! [ -x /usr/local/bin/bun ]; then
  if sudo -n true 2>/dev/null; then
    sudo ln -sf "$HOME/.bun/bin/bun" /usr/local/bin/bun
    sudo ln -sf "$HOME/.bun/bin/bun" /usr/local/bin/bunx
  fi
fi
for rc in "$HOME/.bashrc" "$HOME/.profile"; do
  grep -qs 'HOME/.bun/bin' "$rc" || echo 'export PATH="$HOME/.bun/bin:$PATH"' >> "$rc"
done
scripts="$here/skills/pstack/poteto-mode/scripts"
if [ -f "$scripts/bun.lock" ]; then
  (cd "$scripts" && bun install --frozen-lockfile) || echo "pstack-env: poteto-mode script deps not installed" >&2
fi
bun --version
exit 0
