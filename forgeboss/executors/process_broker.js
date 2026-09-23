"use strict";

/*
 * ForgeBoss derivative experiment.
 *
 * Portions and process-lifecycle design adapted from CodebuffAI/freebuff:
 *   sdk/src/tools/run-terminal-command.ts
 *   upstream commit f385ccbb03b41faf0ce3c2713b8e02fdc0d377f9
 *
 * Upstream is Apache-2.0. See third_party/freebuff/LICENSE and NOTICE.
 * This file is modified for ForgeBoss: CommonJS/Node, no implicit environment
 * inheritance, structured result output, and no runtime authority integration.
 */

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const DEFAULT_OUTPUT_LIMIT = 50000;
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_OUTPUT_LIMIT = 1000000;
const MAX_TIMEOUT_MS = 60 * 60 * 1000;
const MAX_ARGS = 512;
const MAX_ARG_BYTES = 65536;
const MAX_ENV_ENTRIES = 256;
const MAX_ENV_BYTES = 65536;
const KILL_ESCALATION_MS = 1500;
const TRUNCATION_MARKER = "\n[...TRUNCATED DUE TO LENGTH...]\n";
const PROCESS_EXIT_POLL_MS = 25;
const liveChildren = new Set();
let exitSweepInstalled = false;

function stripAnsi(value) {
  return String(value).replace(
    /[\u001B\u009B][[\]()#;?]*(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]+)*)?\u0007|(?:(?:\d{1,4}(?:[;:]\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g,
    "",
  );
}

class BoundedOutputBuffer {
  constructor(maxLength = DEFAULT_OUTPUT_LIMIT) {
    if (!Number.isInteger(maxLength) || maxLength < TRUNCATION_MARKER.length) {
      throw new Error("output limit must be an integer large enough for the truncation marker");
    }
    this.maxLength = maxLength;
    const retained = maxLength - TRUNCATION_MARKER.length;
    this.headLimit = Math.ceil(retained / 2);
    this.tailLimit = Math.floor(retained / 2);
    this.head = "";
    this.tail = "";
    this.truncated = false;
  }

  append(value) {
    const normalized = stripAnsi(value);
    if (!normalized) return;
    if (!this.truncated) {
      const combined = this.head + normalized;
      if (combined.length <= this.maxLength) {
        this.head = combined;
        return;
      }
      this.truncated = true;
      this.head = combined.slice(0, this.headLimit);
      this.tail = this.tailLimit ? combined.slice(-this.tailLimit) : "";
      return;
    }
    if (this.tailLimit) {
      this.tail = (this.tail + normalized).slice(-this.tailLimit);
    }
  }

  format() {
    return this.truncated
      ? this.head + TRUNCATION_MARKER + this.tail
      : this.head;
  }
}

function rewriteWindowsNulRedirects(command) {
  if (typeof command !== "string") throw new TypeError("command must be a string");
  return command.replace(/([<>]\s*)nul(?![\w.])/gi, "$1/dev/null");
}

function windowsSystemFile(relativePath, label) {
  const rootRaw = process.env.SystemRoot || process.env.WINDIR;
  if (typeof rootRaw !== "string" || !rootRaw.trim() || !path.isAbsolute(rootRaw)) {
    throw new Error("Windows SystemRoot is unavailable for " + label);
  }
  const root = fs.realpathSync.native
    ? fs.realpathSync.native(rootRaw)
    : fs.realpathSync(rootRaw);
  const candidate = path.join(root, relativePath);
  const resolved = canonicalFile(candidate, label);
  const rel = path.relative(root, resolved);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(label + " escaped Windows SystemRoot");
  }
  return resolved;
}

function sweepWindowsDescendants(rootPid) {
  if (!Number.isInteger(rootPid) || rootPid <= 0) {
    return { ok: false, error: "invalid root pid" };
  }
  try {
    const powershell = windowsSystemFile(
      path.join("System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      "Windows PowerShell",
    );
    const script = canonicalFile(
      path.join(__dirname, "windows_process_tree.ps1"),
      "Windows process-tree cleanup script",
    );
    const result = spawnSync(
      powershell,
      [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script,
        "-RootPid",
        String(rootPid),
      ],
      {
        stdio: "ignore",
        windowsHide: true,
        timeout: 10000,
        shell: false,
      },
    );
    if (!result.error && result.status === 0) return { ok: true, error: null };
    return {
      ok: false,
      error: result.error
        ? result.error.name + ": " + result.error.message
        : "Windows descendant sweep exit " + String(result.status),
    };
  } catch (error) {
    return { ok: false, error: error.name + ": " + error.message };
  }
}

function isProcessTreeAlive(child) {
  if (!child || !child.pid) return false;
  if (os.platform() === "win32") {
    return child.exitCode === null && child.signalCode === null;
  }
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForProcessTreeExit(child, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (isProcessTreeAlive(child) && Date.now() < deadline) {
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, PROCESS_EXIT_POLL_MS);
      if (timer.unref) timer.unref();
    });
  }
  return !isProcessTreeAlive(child);
}

function installExitSweep() {
  if (exitSweepInstalled) return;
  exitSweepInstalled = true;
  process.on("exit", () => {
    for (const child of liveChildren) {
      try {
        killProcessTree(child, "SIGKILL");
        if (os.platform() === "win32" && child && child.pid) {
          sweepWindowsDescendants(child.pid);
        }
      } catch {
      }
    }
  });
}

function killProcessTree(child, signal = "SIGTERM") {
  if (!child || !child.pid) return false;

  if (os.platform() === "win32") {
    let taskkill;
    try {
      taskkill = windowsSystemFile(
        path.join("System32", "taskkill.exe"),
        "Windows taskkill",
      );
    } catch {
      taskkill = null;
    }
    const result = taskkill ? spawnSync(
      taskkill,
      ["/pid", String(child.pid), "/t", "/f"],
      {
        stdio: "ignore",
        windowsHide: true,
        timeout: 5000,
        shell: false,
      },
    ) : null;
    if (result && !result.error && result.status === 0) return true;
  } else {
    try {
      process.kill(-child.pid, signal);
      return true;
    } catch {
    }
  }

  try {
    return child.kill(signal);
  } catch {
    return false;
  }
}

function canonicalFile(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(label + " is required");
  if (!path.isAbsolute(value)) throw new TypeError(label + " must be an absolute path");
  let resolved;
  try {
    resolved = fs.realpathSync.native ? fs.realpathSync.native(value) : fs.realpathSync(value);
  } catch (error) {
    throw new TypeError(label + " is unavailable: " + error.code);
  }
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch (error) {
    throw new TypeError(label + " cannot be inspected: " + error.code);
  }
  if (!stat.isFile()) throw new TypeError(label + " must be a file");
  return resolved;
}

function canonicalDir(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(label + " is required");
  if (!path.isAbsolute(value)) throw new TypeError(label + " must be an absolute path");
  let resolved;
  try {
    resolved = fs.realpathSync.native ? fs.realpathSync.native(value) : fs.realpathSync(value);
  } catch (error) {
    throw new TypeError(label + " is unavailable: " + error.code);
  }
  if (!fs.statSync(resolved).isDirectory()) throw new TypeError(label + " must be a directory");
  return resolved;
}

function validateEnv(value) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("env must be an object");
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError("env must be a plain object");
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_ENV_ENTRIES) throw new TypeError("env has too many entries");
  let total = 0;
  const seen = new Set();
  const out = {};
  for (const [key, val] of entries) {
    if (!key || key.includes("\0") || key.includes("=")) {
      throw new TypeError("env contains an invalid key");
    }
    if (typeof val !== "string" || val.includes("\0")) {
      throw new TypeError("env values must be NUL-free strings");
    }
    const identity = os.platform() === "win32" ? key.toLowerCase() : key;
    if (seen.has(identity)) throw new TypeError("env contains duplicate platform-equivalent keys");
    seen.add(identity);
    total += Buffer.byteLength(key, "utf8") + Buffer.byteLength(val, "utf8") + 2;
    if (total > MAX_ENV_BYTES) throw new TypeError("env is too large");
    out[key] = val;
  }
  return out;
}

function validateRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("request must be an object");
  }
  const executable = canonicalFile(request.executable, "executable");
  const cwd = canonicalDir(request.cwd, "cwd");

  if (!Array.isArray(request.args) || request.args.some((v) => typeof v !== "string")) {
    throw new TypeError("args must be a string array");
  }
  if (request.args.length > MAX_ARGS) throw new TypeError("args has too many entries");
  let argBytes = 0;
  const args = request.args.map((value) => {
    if (value.includes("\0")) throw new TypeError("args must not contain NUL");
    argBytes += Buffer.byteLength(value, "utf8") + 1;
    if (argBytes > MAX_ARG_BYTES) throw new TypeError("args are too large");
    return value;
  });

  const env = validateEnv(request.env);

  if (
    request.signal !== undefined
    && (
      !request.signal
      || typeof request.signal !== "object"
      || typeof request.signal.addEventListener !== "function"
      || typeof request.signal.removeEventListener !== "function"
      || typeof request.signal.aborted !== "boolean"
    )
  ) {
    throw new TypeError("signal must be an AbortSignal");
  }

  const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new TypeError("timeoutMs must be a positive integer within the broker cap");
  }
  const maxOutput = request.maxOutput ?? DEFAULT_OUTPUT_LIMIT;
  if (
    !Number.isInteger(maxOutput)
    || maxOutput < TRUNCATION_MARKER.length
    || maxOutput > MAX_OUTPUT_LIMIT
  ) {
    throw new TypeError("maxOutput is outside the broker cap");
  }
  return { timeoutMs, maxOutput, executable, cwd, args, env };
}

async function runProcess(request) {
  const { timeoutMs, maxOutput, executable, cwd, args, env } = validateRequest(request);
  const startedAt = Date.now();
  const stdout = new BoundedOutputBuffer(maxOutput);
  const stderr = new BoundedOutputBuffer(maxOutput);
  let child;
  let timedOut = false;
  let aborted = false;
  let escalationTimer = null;
  let timeoutTimer = null;
  let abortHandler = null;
  let cleanupError = null;

  const resultBase = () => ({
    pid: child && child.pid ? child.pid : null,
    exitCode: child ? child.exitCode : null,
    signal: child ? child.signalCode : null,
    timedOut,
    aborted,
    stdout: stdout.format(),
    stderr: stderr.format(),
    durationMs: Date.now() - startedAt,
    cleanupOk: cleanupError === null,
    cleanupError,
  });

  try {
    child = spawn(executable, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      detached: true,
      windowsHide: true,
    });
  } catch (error) {
    return {
      ...resultBase(),
      startError: error.name + ": " + error.message,
    };
  }

  installExitSweep();
  liveChildren.add(child);

  child.stdout.on("data", (chunk) => stdout.append(chunk.toString("utf8")));
  child.stderr.on("data", (chunk) => stderr.append(chunk.toString("utf8")));

  const terminate = (reason) => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    if (reason === "timeout") timedOut = true;
    if (reason === "abort") aborted = true;
    killProcessTree(child, "SIGTERM");
    escalationTimer = setTimeout(() => {
      if (child && child.exitCode === null && child.signalCode === null) {
        killProcessTree(child, "SIGKILL");
      }
    }, KILL_ESCALATION_MS);
    if (escalationTimer.unref) escalationTimer.unref();
  };

  timeoutTimer = setTimeout(() => terminate("timeout"), timeoutMs);
  if (timeoutTimer.unref) timeoutTimer.unref();

  if (request.signal) {
    abortHandler = () => terminate("abort");
    if (request.signal.aborted) abortHandler();
    else request.signal.addEventListener("abort", abortHandler, { once: true });
  }

  const completion = await new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    child.once("error", (error) => finish({ startError: error.name + ": " + error.message }));
    child.once("close", (code, signal) => finish({ code, signal }));
  });

  clearTimeout(timeoutTimer);
  if (escalationTimer) clearTimeout(escalationTimer);
  if (request.signal && abortHandler && request.signal.removeEventListener) {
    request.signal.removeEventListener("abort", abortHandler);
  }

  // POSIX detached children own a process group. The shell/direct child can
  // exit while one of its non-detached descendants is still alive, so close
  // is not sufficient proof that the owned tree is gone.
  if (os.platform() !== "win32" && isProcessTreeAlive(child)) {
    killProcessTree(child, "SIGTERM");
    if (!(await waitForProcessTreeExit(child, KILL_ESCALATION_MS))) {
      killProcessTree(child, "SIGKILL");
      await waitForProcessTreeExit(child, KILL_ESCALATION_MS);
    }
    if (isProcessTreeAlive(child)) {
      cleanupError = "POSIX process group survived broker cleanup";
    }
  } else if (os.platform() === "win32" && child && child.pid) {
    const swept = sweepWindowsDescendants(child.pid);
    if (!swept.ok) cleanupError = swept.error || "Windows descendant cleanup failed";
  }
  liveChildren.delete(child);

  return {
    ...resultBase(),
    exitCode: Object.prototype.hasOwnProperty.call(completion, "code")
      ? completion.code
      : child.exitCode,
    signal: Object.prototype.hasOwnProperty.call(completion, "signal")
      ? completion.signal
      : child.signalCode,
    ...(completion.startError ? { startError: completion.startError } : {}),
  };
}

module.exports = {
  BoundedOutputBuffer,
  DEFAULT_OUTPUT_LIMIT,
  TRUNCATION_MARKER,
  isProcessTreeAlive,
  killProcessTree,
  sweepWindowsDescendants,
  rewriteWindowsNulRedirects,
  runProcess,
};