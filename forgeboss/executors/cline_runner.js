"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

if (process.argv.length < 4) {
  console.error("usage: node cline_runner.js PACKET.json WORKSPACE");
  process.exit(2);
}
if (process.env.FORGEBOSS_ALLOW_PAID_EXECUTOR !== "YES") {
  console.error("FORGEBOSS SAFE STOP: paid executor gate disabled.");
  process.exit(3);
}
if (process.env.FORGEBOSS_ENABLE_QUARANTINED_CLINE !== "YES") {
  console.error("FORGEBOSS SECURITY STOP: Cline host-shell executor is QUARANTINED until explicitly enabled.");
  process.exit(13);
}
if (process.env.FORGEBOSS_OS_ISOLATION_VERIFIED !== "YES") {
  console.error("FORGEBOSS SECURITY STOP: Cline requires verified OS/network isolation.");
  process.exit(13);
}

const packetPath = path.resolve(process.argv[2]);
const workspace = path.resolve(process.argv[3]);
const lease = process.env.FORGEBOSS_EXECUTOR_LEASE || "";
const token = process.env.FORGEBOSS_EXECUTOR_LEASE_TOKEN || "";
if (!lease || !token) {
  console.error("FORGEBOSS SAFE STOP: unified executor lease missing.");
  process.exit(13);
}

const py = process.env.FORGEBOSS_PYTHON || "python";
const guard = path.resolve(__dirname, "..", "security", "executor_guard.py");
let verify = spawnSync(
  py,
  [
    guard,
    "verify",
    "--lease",
    lease,
    "--token",
    token,
    "--packet",
    packetPath,
    "--workspace",
    workspace,
    "--executor",
    "cline",
  ],
  { encoding: "utf8", shell: false, windowsHide: true }
);
if (verify.status !== 0) {
  console.error("FORGEBOSS SAFE STOP: " + (verify.stdout || verify.stderr || "executor lease verification failed"));
  process.exit(13);
}

const packet = JSON.parse(fs.readFileSync(packetPath, "utf8"));
const allowed = Array.isArray(packet.allowed_files) ? packet.allowed_files : [];
if (allowed.length === 0) {
  console.error("FORGEBOSS SAFE STOP: packet has no writable file scope.");
  process.exit(13);
}

const systemPrompt = [
  "You are a coding execution worker inside ForgeBoss.",
  "You are not the controller and have no authority to widen scope.",
  "Never push, merge, deploy, alter GitHub state, access secrets, or edit Git metadata.",
  "Only modify the exact paths explicitly allowed by the task packet.",
  "Run the narrowest useful checks for your changes and report failures truthfully.",
].join("\n");

const prompt = [
  `Objective: ${packet.objective || ""}`,
  `Allowed writes ONLY: ${JSON.stringify(allowed)}`,
  `Context files: ${JSON.stringify(packet.context_files || [])}`,
  "Stop rather than changing an undeclared file.",
].join("\n");

const command = process.platform === "win32" ? "cline.cmd" : "cline";
const dataDir =
  process.env.FORGEBOSS_CLINE_DATA_DIR ||
  path.join(os.homedir(), ".forgeboss", "runtime", "cline-data");

fs.mkdirSync(dataDir, { recursive: true });

const env = { ...process.env };
for (const key of [
  "GH_TOKEN",
  "GITHUB_TOKEN",
  "GITHUB_PAT",
  "FORGEBOSS_EXECUTOR_LEASE_TOKEN",
]) {
  delete env[key];
}

const args = [
  "--json",
  "--auto-approve",
  "true",
  "--cwd",
  workspace,
  "--data-dir",
  dataDir,
  "--timeout",
  process.env.FORGEBOSS_CLINE_TIMEOUT_SECONDS || "900",
  "--retries",
  process.env.FORGEBOSS_CLINE_RETRIES || "3",
  "--system",
  systemPrompt,
];

if (process.env.FORGEBOSS_CLINE_PROVIDER) {
  args.push("--provider", process.env.FORGEBOSS_CLINE_PROVIDER);
}
if (process.env.FORGEBOSS_CLINE_MODEL) {
  args.push("--model", process.env.FORGEBOSS_CLINE_MODEL);
}
args.push(prompt);

const result = spawnSync(command, args, {
  cwd: workspace,
  encoding: "utf8",
  shell: false,
  timeout: 930000,
  windowsHide: true,
  env,
});

process.stdout.write(result.stdout || "");
process.stderr.write(result.stderr || "");
if (result.error) {
  console.error(`FORGEBOSS Cline launch failed: ${result.error.message}`);
  process.exit(4);
}
if ((result.status ?? 5) !== 0) {
  process.exit(result.status ?? 5);
}

let postflight = spawnSync(
  py,
  [
    guard,
    "postflight",
    "--lease",
    lease,
    "--token",
    token,
    "--packet",
    packetPath,
    "--workspace",
    workspace,
    "--executor",
    "cline",
  ],
  { encoding: "utf8", shell: false, windowsHide: true }
);
if (postflight.status !== 0) {
  console.error(
    "FORGEBOSS postflight denied Cline result: " +
      (postflight.stdout || postflight.stderr || "postflight failed")
  );
  process.exit(13);
}
