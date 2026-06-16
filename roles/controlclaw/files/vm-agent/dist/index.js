// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync2 } from "fs";

// src/auth.ts
import { importSPKI, jwtVerify } from "jose";
var saasPublicKey = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
async function verifyRequest(req) {
  if (!saasPublicKey) return null;
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  try {
    const key = await importSPKI(saasPublicKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    return payload;
  } catch {
    return null;
  }
}
async function requireAuth(req, res) {
  const payload = await verifyRequest(req);
  if (!payload) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return false;
  }
  return true;
}

// src/ready.ts
import { readFileSync } from "fs";
import { importPKCS8, SignJWT } from "jose";
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
function readKeyFile(name) {
  try {
    return readFileSync(`${KEYS_DIR}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signReadyToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function reportReady() {
  const vmId = readKeyFile("vm_id");
  const readyUrl = readKeyFile("ready_api_url");
  const privateKey = readKeyFile("vm_private_key.pem");
  if (!vmId || !readyUrl || !privateKey) {
    console.warn(
      "[ready] missing vm_id / ready_api_url / vm_private_key.pem in KEYS_DIR \u2014 skipping ready report"
    );
    return;
  }
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signReadyToken(vmId, privateKey);
      const res = await fetch(readyUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        console.log(`[ready] reported ready to SaaS (attempt ${attempt})`);
        return;
      }
      console.warn(`[ready] attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[ready] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[ready] gave up reporting ready after ${maxAttempts} attempts`);
}

// src/routes/health.ts
import { execSync } from "child_process";
function getServiceStatus(service) {
  try {
    const result = execSync(`systemctl is-active ${service}`, { encoding: "utf-8", timeout: 5e3 }).trim();
    return result === "active" ? "running" : "stopped";
  } catch {
    try {
      execSync(`systemctl cat ${service}`, { encoding: "utf-8", timeout: 5e3 });
      return "stopped";
    } catch {
      return "not-installed";
    }
  }
}
function handleHealth(res) {
  const services = {
    docker: getServiceStatus("docker"),
    tailscaled: getServiceStatus("tailscaled"),
    "browser-stream": getServiceStatus("browser-stream"),
    openclaw: getServiceStatus("openclaw")
  };
  let ps = "";
  try {
    ps = execSync("ps faux", { encoding: "utf-8", timeout: 5e3 });
  } catch {
    ps = "Failed to get process list";
  }
  const response = {
    status: "ok",
    uptime: process.uptime(),
    services,
    ps
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(response));
}

// src/routes/openclaw.ts
import { execSync as execSync2 } from "child_process";
var SERVICE = "openclaw";
var EXEC_TIMEOUT_MS = 5e3;
var ACTION_TIMEOUT_MS = 3e4;
function runIsActive() {
  try {
    return execSync2(`systemctl is-active ${SERVICE}`, { encoding: "utf-8", timeout: EXEC_TIMEOUT_MS }).trim();
  } catch (err) {
    const stdout = err.stdout;
    if (stdout) return stdout.toString().trim();
    return "unknown";
  }
}
function runStatusSummary() {
  try {
    return execSync2(`systemctl status ${SERVICE} --no-pager -n 5`, {
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT_MS
    }).trim();
  } catch (err) {
    const stdout = err.stdout;
    return stdout ? stdout.toString().trim() : "status unavailable";
  }
}
function send(res, statusCode, body) {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
function runAction(action) {
  try {
    execSync2(`sudo systemctl ${action} ${SERVICE}`, { encoding: "utf-8", timeout: ACTION_TIMEOUT_MS });
    return { ok: true };
  } catch (err) {
    const message = err.stderr?.toString().trim() || (err instanceof Error ? err.message : "systemctl failed");
    return { ok: false, error: message };
  }
}
function handleAction(res, action) {
  const result = runAction(action);
  const status = runIsActive();
  const summary = runStatusSummary();
  send(res, result.ok ? 200 : 500, {
    ok: result.ok,
    action,
    active: status === "active",
    status,
    message: result.ok ? summary : result.error ?? "failed"
  });
}
function handleStart(res) {
  handleAction(res, "start");
}
function handleStop(res) {
  handleAction(res, "stop");
}
function handleRestart(res) {
  handleAction(res, "restart");
}
function handleStatus(res) {
  const status = runIsActive();
  const summary = runStatusSummary();
  send(res, 200, {
    ok: true,
    action: "status",
    active: status === "active",
    status,
    message: summary
  });
}

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
try {
  const saasPublicKey2 = readFileSync2(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
var server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  if (!await requireAuth(req, res)) return;
  if (url.pathname === "/health" && req.method === "GET") {
    handleHealth(res);
    return;
  }
  if (url.pathname === "/start" && req.method === "POST") {
    handleStart(res);
    return;
  }
  if (url.pathname === "/stop" && req.method === "POST") {
    handleStop(res);
    return;
  }
  if (url.pathname === "/restart" && req.method === "POST") {
    handleRestart(res);
    return;
  }
  if (url.pathname === "/status" && req.method === "GET") {
    handleStatus(res);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, "0.0.0.0", () => {
  console.log(`ControlClaw agent listening on port ${PORT}`);
  void reportReady();
});
