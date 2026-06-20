// src/index.ts
import { readFileSync, writeFileSync, existsSync, watch } from "fs";

// src/detect.ts
var MATCHERS = [
  { type: "github", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, domain: "github.com", scope: "confirmed" },
  { type: "openai", re: /\bsk-[A-Za-z0-9]{20,}\b/g, domain: "api.openai.com", scope: "confirmed" },
  { type: "aws", re: /\bAKIA[0-9A-Z]{16}\b/g, domain: "amazonaws.com", scope: "confirmed" },
  { type: "slack", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, domain: "slack.com", scope: "confirmed" },
  { type: "stripe", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g, domain: "api.stripe.com", scope: "confirmed" },
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, domain: "", scope: "unconfirmed" }
];
function entropy(s) {
  const freq = /* @__PURE__ */ new Map();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
var ASSIGN_RE = /(?:[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|API|CRED)[A-Za-z0-9_]*)\s*[:=]\s*["']?([A-Za-z0-9_\-+/.=]{20,})["']?/gi;
var ENTROPY_THRESHOLD = 3.6;
var counter = 0;
function placeholderFor(type) {
  if (type === "generic" || type === "jwt") return `__secret_${++counter}`;
  return `__${type}_credentials`;
}
function detect(text) {
  const found = [];
  const taken = [];
  const overlaps = (s, e) => taken.some(([a2, b]) => s < b && e > a2);
  for (const m of MATCHERS) {
    m.re.lastIndex = 0;
    let match;
    while (match = m.re.exec(text)) {
      const start = match.index;
      const end = start + match[0].length;
      if (overlaps(start, end)) continue;
      taken.push([start, end]);
      found.push({
        value: match[0],
        start,
        end,
        type: m.type,
        placeholder: placeholderFor(m.type),
        matchDomain: m.domain,
        scope: m.scope
      });
    }
  }
  ASSIGN_RE.lastIndex = 0;
  let a;
  while (a = ASSIGN_RE.exec(text)) {
    const value = a[1];
    const start = a.index + a[0].indexOf(value);
    const end = start + value.length;
    if (overlaps(start, end)) continue;
    if (entropy(value) < ENTROPY_THRESHOLD) continue;
    taken.push([start, end]);
    found.push({
      value,
      start,
      end,
      type: "generic",
      placeholder: placeholderFor("generic"),
      matchDomain: "",
      scope: "unconfirmed"
    });
  }
  return found.sort((x, y) => x.start - y.start);
}
function scanAndRedact(text) {
  const detections = detect(text);
  let redacted = "";
  let cursor = 0;
  for (const d of detections) {
    redacted += text.slice(cursor, d.start) + d.placeholder;
    cursor = d.end;
  }
  redacted += text.slice(cursor);
  return {
    redacted,
    controlPlaneRecords: detections.map((d) => ({
      placeholder: d.placeholder,
      matchDomain: d.matchDomain,
      scope: d.scope
    })),
    storePushes: detections.map((d) => ({
      placeholder: d.placeholder,
      matchDomain: d.matchDomain,
      secret: d.value
    }))
  };
}

// src/index.ts
var PATHS = (process.env.WATCH_PATHS ?? process.argv.slice(2).join(",")).split(",").filter(Boolean);
var SCAN_ONCE = process.env.SCAN_ONCE === "1";
var STORE_PUSH_URL = process.env.CREDENTIAL_PUSH_URL ?? "";
var REGISTRATION_URL = process.env.REGISTRATION_URL ?? "";
var RECORDS_OUT = process.env.RECORDS_OUT ?? "";
async function post(url, body, token) {
  if (!url) return;
  await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...token ? { Authorization: `Bearer ${token}` } : {} },
    body: JSON.stringify(body)
  });
}
async function processFile(path) {
  if (!existsSync(path)) return;
  const original = readFileSync(path, "utf8");
  const result = scanAndRedact(original);
  if (result.storePushes.length === 0) return;
  if (result.redacted !== original) {
    writeFileSync(path, result.redacted);
    console.log(`[config-monitor] redacted ${result.storePushes.length} secret(s) in ${path}`);
  }
  for (const push of result.storePushes) {
    await post(STORE_PUSH_URL, { ...push, source: path });
  }
  for (const rec of result.controlPlaneRecords) {
    await post(REGISTRATION_URL, { ...rec, source: path, detected_at: (/* @__PURE__ */ new Date()).toISOString() });
  }
  if (RECORDS_OUT) {
    writeFileSync(RECORDS_OUT, JSON.stringify(result.controlPlaneRecords, null, 2));
  }
}
async function main() {
  if (PATHS.length === 0) {
    console.error("usage: WATCH_PATHS=a,b config-monitor  (or pass paths as args)");
    process.exit(64);
  }
  for (const p of PATHS) await processFile(p);
  if (SCAN_ONCE) {
    console.log("[config-monitor] scan-once complete");
    process.exit(0);
  }
  console.log(`[config-monitor] watching ${PATHS.length} path(s)`);
  for (const p of PATHS) {
    if (!existsSync(p)) continue;
    watch(p, { persistent: true }, () => void processFile(p).catch((e) => console.error(e)));
  }
}
void main();
