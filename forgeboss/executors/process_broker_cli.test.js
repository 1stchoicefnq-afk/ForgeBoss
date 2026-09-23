"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const os = require("node:os");
const path = require("node:path");

const CLI = path.resolve(__dirname, "process_broker_cli.js");
const CWD = path.resolve(__dirname, "..", "..");

function call(request, options = {}) {
  return spawnSync(
    process.execPath,
    [CLI],
    {
      cwd: CWD,
      input: typeof request === "string" ? request : JSON.stringify(request),
      encoding: "utf8",
      windowsHide: true,
      timeout: options.timeout || 10000,
      env: options.env || process.env,
      maxBuffer: 2 * 1024 * 1024,
      shell: false,
    },
  );
}

function body(result) {
  assert.ok(result.stdout, result.stderr || "missing stdout");
  return JSON.parse(result.stdout.trim());
}

test("stdin bridge executes exact request and returns bounded result", () => {
  const result = call({
    schema: 1,
    executable: process.execPath,
    args: ["-e", "console.log('OUT'); console.error('ERR')"],
    cwd: CWD,
    env: {},
    timeoutMs: 5000,
    maxOutput: 1000,
  });
  assert.equal(result.status, 0, result.stderr);
  const parsed = body(result);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.result.exitCode, 0);
  assert.equal(parsed.result.cleanupOk, true, parsed.result.cleanupError);
  assert.match(parsed.result.stdout, /OUT/);
  assert.match(parsed.result.stderr, /ERR/);
});

test("bridge rejects unexpected keys without echoing secret request data", () => {
  const secret = "DO-NOT-ECHO-THIS-SECRET";
  const result = call({
    schema: 1,
    executable: process.execPath,
    args: [],
    cwd: CWD,
    env: { OPENAI_API_KEY: secret },
    timeoutMs: 1000,
    maxOutput: 1000,
    surprise: secret,
  });
  assert.equal(result.status, 2);
  const combined = (result.stdout || "") + (result.stderr || "");
  assert.doesNotMatch(combined, new RegExp(secret));
  const parsed = body(result);
  assert.equal(parsed.ok, false);
  assert.match(parsed.error.message, /unexpected broker request keys/);
});

test("bridge rejects relative executable before target start", () => {
  const result = call({
    schema: 1,
    executable: "node",
    args: [],
    cwd: CWD,
    env: {},
    timeoutMs: 1000,
    maxOutput: 1000,
  });
  assert.equal(result.status, 3);
  const parsed = body(result);
  assert.equal(parsed.ok, false);
  assert.match(parsed.error.message, /executable must be an absolute path/);
});

test("bridge enforces stdin byte cap", () => {
  const oversized = JSON.stringify({
    schema: 1,
    executable: process.execPath,
    args: [],
    cwd: CWD,
    env: {},
    timeoutMs: 1000,
    maxOutput: 1000,
    padding: "x".repeat((2 * 1024 * 1024) + 100),
  });
  const result = call(oversized, { timeout: 15000 });
  assert.equal(result.status, 2);
  const parsed = body(result);
  assert.equal(parsed.ok, false);
  assert.match(parsed.error.message, /stdin byte cap/);
});

test("bridge does not expose target env through its own diagnostics", () => {
  const secret = "provider-secret-123";
  const result = call({
    schema: 1,
    executable: process.execPath,
    args: ["-e", "process.stdout.write(process.env.OPENAI_API_KEY ? 'present' : 'missing')"],
    cwd: CWD,
    env: { OPENAI_API_KEY: secret },
    timeoutMs: 5000,
    maxOutput: 1000,
  });
  assert.equal(result.status, 0);
  const parsed = body(result);
  assert.equal(parsed.result.stdout, "present");
  assert.doesNotMatch(JSON.stringify(parsed), new RegExp(secret));
});

test("Windows cleanup failure makes bridge fail closed", { skip: os.platform() !== "win32" }, () => {
  const env = { ...process.env, SystemRoot: "Z:\\definitely-missing-system-root", WINDIR: "" };
  const result = call({
    schema: 1,
    executable: process.execPath,
    args: ["-e", "process.stdout.write('done')"],
    cwd: CWD,
    env: {},
    timeoutMs: 5000,
    maxOutput: 1000,
  }, { env });
  assert.equal(result.status, 13);
  const parsed = body(result);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.result.cleanupOk, false);
});
