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
const os = require("os");

const DEFAULT_OUTPUT_LIMIT = 50000;
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const KILL_ESCALATION_MS = 1500;
const TRUNCATION_MARKER = "\n[...TRUNCATED DUE TO LENGTH...]\n";

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

function killProcessTree(child, signal = "SIGTERM") {
  if (!child || !child.pid) return false;

  if (os.platform() === "win32") {
    const result = spawnSync(
      "taskkill.exe",
      ["/pid", String(child.pid), "/t", "/f"],
      {
        stdio: "ignore",
        windowsHide: true,
        timeout: 5000,
      },
    );
    if (!result.error && result.status === 0) return true;
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

function validateRequest(request) {
  if (!request || typeof request !== "object") throw new TypeError("request must be an object");
  if (typeof request.executable !== "string" || !request.executable.trim()) {
    throw new TypeError("executable is required");
  }
  if (!Array.isArray(request.args) || request.args.some((v) => typeof v !== "string")) {
    throw new TypeError("args must be a string array");
  }
  if (typeof request.cwd !== "string" || !request.cwd) throw new TypeError("cwd is required");
  if (request.env === undefined) request.env = {};
  if (!request.env || typeof request.env !== "object" || Array.isArray(request.env)) {
    throw new TypeError("env must be an object");
  }
  const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive integer");
  }
  const maxOutput = request.maxOutput ?? DEFAULT_OUTPUT_LIMIT;
  if (!Number.isInteger(maxOutput) || maxOutput < TRUNCATION_MARKER.length) {
    throw new TypeError("maxOutput is invalid");
  }
  return { timeoutMs, maxOutput };
}

async function runProcess(request) {
  const { timeoutMs, maxOutput } = validateRequest(request);
  const startedAt = Date.now();
  const stdout = new BoundedOutputBuffer(maxOutput);
  const stderr = new BoundedOutputBuffer(maxOutput);
  let child;
  let timedOut = false;
  let aborted = false;
  let escalationTimer = null;
  let timeoutTimer = null;
  let abortHandler = null;

  const resultBase = () => ({
    pid: child && child.pid ? child.pid : null,
    exitCode: child ? child.exitCode : null,
    signal: child ? child.signalCode : null,
    timedOut,
    aborted,
    stdout: stdout.format(),
    stderr: stderr.format(),
    durationMs: Date.now() - startedAt,
  });

  try {
    child = spawn(request.executable, request.args, {
      cwd: request.cwd,
      env: { ...request.env },
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
    if (typeof request.signal.addEventListener !== "function") {
      clearTimeout(timeoutTimer);
      killProcessTree(child, "SIGKILL");
      throw new TypeError("signal must be an AbortSignal");
    }
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
  killProcessTree,
  rewriteWindowsNulRedirects,
  runProcess,
};
