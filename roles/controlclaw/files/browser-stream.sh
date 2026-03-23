#!/usr/bin/env bash
set -euo pipefail

export DISPLAY=:1
export HOME=/home/controlclaw
export XDG_CONFIG_HOME="${HOME}/.config"
export XDG_CACHE_HOME="${HOME}/.cache"

CDP_PORT="${CONTROLCLAW_BROWSER_CDP_PORT:-9222}"
VNC_PORT="${CONTROLCLAW_BROWSER_VNC_PORT:-5900}"
NOVNC_PORT="${CONTROLCLAW_BROWSER_NOVNC_PORT:-6080}"

mkdir -p "${HOME}/.chrome" "${XDG_CONFIG_HOME}" "${XDG_CACHE_HOME}" "${HOME}/.vnc"

# Start Xvfb
Xvfb :1 -screen 0 1280x800x24 -ac -nolisten tcp &
sleep 2

# Calculate Chrome CDP port (internal, offset from exposed port)
if [[ "${CDP_PORT}" -ge 65535 ]]; then
  CHROME_CDP_PORT="$((CDP_PORT - 1))"
else
  CHROME_CDP_PORT="$((CDP_PORT + 1))"
fi

# Start Chromium
google-chrome-stable \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=${CHROME_CDP_PORT} \
  --user-data-dir=${HOME}/.chrome \
  --no-first-run \
  --no-default-browser-check \
  --disable-dev-shm-usage \
  --disable-background-networking \
  --disable-features=TranslateUI \
  --disable-breakpad \
  --disable-crash-reporter \
  --metrics-recording-only \
  --no-sandbox \
  --disable-setuid-sandbox \
  about:blank &

# Wait for Chrome to start
for _ in $(seq 1 50); do
  if curl -sS --max-time 1 "http://127.0.0.1:${CHROME_CDP_PORT}/json/version" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

# Expose CDP via socat
socat "TCP-LISTEN:${CDP_PORT},fork,reuseaddr,bind=127.0.0.1" "TCP:127.0.0.1:${CHROME_CDP_PORT}" &

# Start x11vnc (no password, localhost only - auth proxy to be added later)
x11vnc -display :1 -rfbport "${VNC_PORT}" -shared -forever -nopw -localhost &

# Start noVNC websockify (localhost only - auth proxy to be added later)
websockify --web /usr/share/novnc/ 127.0.0.1:"${NOVNC_PORT}" "localhost:${VNC_PORT}" &

# Wait for any process to exit
wait -n
