"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  BoundedOutputBuffer,
  TRUNCATION_MARKER,
  rewriteWindowsNulRedirects,
  runProcess,
} = require("./process_broker");

const CWD = path.resolve(__dirname, "..", "..");

test("bounded buffer retains head and tail without unbounded growth", () => {
  const buffer = new BoundedOutputBuffer(100);
  buffer.append("A".repeat(200));
  const out = buffer.format();
  assert.equal(out.length, 100);
  assert.ok(out.includes(TRUNCATION_MARKER));
  assert.ok(out.startsWith("A"));
  assert.ok(out.endsWith("A"));
});

test("Windows nul redirection is rewritten for Git Bash semantics", () => {
  assert.equal(
    rewriteWindowsNulRedirects("echo hi > nul 2>nul"),
    "echo hi > /dev/null 2>/dev/null",
  );
  assert.equal(rewriteWindowsNulRedirects("echo nul.txt"), "echo nul.txt");
});

test("runProcess captures stdout/stderr and exit code", async () => {
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", "console.log('OUT'); console.error('ERR')"],
    cwd: CWD,
    env: {},
    timeoutMs: 5000,
  });
  assert.equal(result.startError, undefined);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /OUT/);
  assert.match(result.stderr, /ERR/);
  assert.equal(result.timedOut, false);
});

test("runProcess does not inherit host environment by default", async () => {
  const key = "FORGEBOSS_PROCESS_BROKER_SECRET_TEST";
  const previous = process.env[key];
  process.env[key] = "must-not-leak";
  try {
    const result = await runProcess({
      executable: process.execPath,
      args: ["-e", "process.stdout.write(process.env.FORGEBOSS_PROCESS_BROKER_SECRET_TEST || 'missing')"],
      cwd: CWD,
      env: {},
      timeoutMs: 5000,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "missing");
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
});

test("runProcess bounds noisy command output", async () => {
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(5000))"],
    cwd: CWD,
    env: {},
    timeoutMs: 5000,
    maxOutput: 200,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.length, 200);
  assert.ok(result.stdout.includes(TRUNCATION_MARKER));
});

test("runProcess times out and terminates owned process", async () => {
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", "setInterval(()=>{}, 1000)"],
    cwd: CWD,
    env: {},
    timeoutMs: 100,
  });
  assert.equal(result.timedOut, true);
  assert.ok(result.durationMs < 5000);
});

test("runProcess returns structured start failure without shell fallback", async () => {
  const fake = path.join(CWD, "definitely-does-not-exist-forgeboss-executable");
  const result = await runProcess({
    executable: fake,
    args: [],
    cwd: CWD,
    env: {},
    timeoutMs: 1000,
  });
  assert.match(result.startError || "", /ENOENT|not found/i);
  assert.equal(result.timedOut, false);
});

test("AbortSignal cancels a running process", async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 100);
  if (timer.unref) timer.unref();
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", "setInterval(()=>{}, 1000)"],
    cwd: CWD,
    env: {},
    timeoutMs: 5000,
    signal: controller.signal,
  });
  assert.equal(result.aborted, true);
  assert.equal(result.timedOut, false);
});
