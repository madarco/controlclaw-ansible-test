// src/index.ts
import { createServer } from "http";
import { readFileSync } from "fs";

// src/auth.ts
import jwt from "jsonwebtoken";
var saasPublicKey = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
function verifyRequest(req) {
  if (!saasPublicKey) return null;
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  try {
    return jwt.verify(token, saasPublicKey, { algorithms: ["EdDSA"] });
  } catch {
    return null;
  }
}
function requireAuth(req, res) {
  const payload = verifyRequest(req);
  if (!payload) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return false;
  }
  return true;
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
    "controlclaw-agent": "running"
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

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
try {
  const saasPublicKey2 = readFileSync(`${KEYS_DIR}/saas_public_key.pem`, "utf-8");
  setSaasPublicKey(saasPublicKey2);
  console.log("Loaded SaaS public key");
} catch (err) {
  console.error("Failed to load SaaS public key:", err);
  process.exit(1);
}
var server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  if (!requireAuth(req, res)) return;
  if (url.pathname === "/health" && req.method === "GET") {
    handleHealth(res);
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});
server.listen(PORT, "0.0.0.0", () => {
  console.log(`ControlClaw agent listening on port ${PORT}`);
});
