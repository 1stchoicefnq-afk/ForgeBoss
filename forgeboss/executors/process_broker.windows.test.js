"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");

const { runProcess } = require("./process_broker");

const WINDOWS = os.platform() === "win32";
const CWD = path.resolve(__dirname, "..", "..");

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitGone(pid, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!pidAlive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return !pidAlive(pid);
}

function treeScript() {
  return [
    "const cp=require('child_process')",
    "const child=cp.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'})",
    "console.log(child.pid)",
    "setInterval(()=>{},1000)",
  ].join(";");
}

test("windows timeout kills direct process and descendant tree", { skip: !WINDOWS }, async () => {
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", treeScript()],
    cwd: CWD,
    env: {},
    timeoutMs: 300,
  });
  assert.equal(result.timedOut, true);
  const descendantPid = Number(result.stdout.trim().split(/\s+/)[0]);
  assert.ok(Number.isInteger(descendantPid) && descendantPid > 0);
  assert.equal(await waitGone(descendantPid), true, "descendant " + descendantPid + " survived timeout");
  assert.ok(result.durationMs < 5000);
});

test("windows AbortSignal kills descendant tree", { skip: !WINDOWS }, async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300);
  const result = await runProcess({
    executable: process.execPath,
    args: ["-e", treeScript()],
    cwd: CWD,
    env: {},
    timeoutMs: 10000,
    signal: controller.signal,
  });
  clearTimeout(timer);
  assert.equal(result.aborted, true);
  assert.equal(result.timedOut, false);
  const descendantPid = Number(result.stdout.trim().split(/\s+/)[0]);
  assert.ok(Number.isInteger(descendantPid) && descendantPid > 0);
  assert.equal(await waitGone(descendantPid), true, "descendant " + descendantPid + " survived abort");
});

test("windows repeated timeout and abort cycles leave no recorded descendants", { skip: !WINDOWS }, async () => {
  const descendants = [];
  for (let i = 0; i < 10; i += 1) {
    const useAbort = i % 2 === 1;
    const controller = new AbortController();
    let timer = null;
    if (useAbort) timer = setTimeout(() => controller.abort(), 100);

    const result = await runProcess({
      executable: process.execPath,
      args: ["-e", treeScript()],
      cwd: CWD,
      env: {},
      timeoutMs: useAbort ? 5000 : 100,
      signal: useAbort ? controller.signal : undefined,
    });

    if (timer) clearTimeout(timer);
    const pid = Number(result.stdout.trim().split(/\s+/)[0]);
    assert.ok(Number.isInteger(pid) && pid > 0);
    descendants.push(pid);
    if (useAbort) assert.equal(result.aborted, true);
    else assert.equal(result.timedOut, true);
  }

  for (const pid of descendants) {
    assert.equal(await waitGone(pid), true, "descendant " + pid + " survived repeated cancellation");
  }
});

test("windows child receives only explicitly supplied environment", { skip: !WINDOWS }, async () => {
  const key = "FORGEBOSS_WINDOWS_BROKER_SECRET";
  const previous = process.env[key];
  process.env[key] = "must-not-leak";
  try {
    const result = await runProcess({
      executable: process.execPath,
      args: [
        "-e",
        "process.stdout.write(JSON.stringify({secret:process.env.FORGEBOSS_WINDOWS_BROKER_SECRET||null, explicit:process.env.EXPLICIT||null}))",
      ],
      cwd: CWD,
      env: { EXPLICIT: "allowed" },
      timeoutMs: 5000,
    });
    assert.equal(result.exitCode, 0);
    assert.deepEqual(JSON.parse(result.stdout), { secret: null, explicit: "allowed" });
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
});

test("windows broker rejects relative executable and cwd before spawn", { skip: !WINDOWS }, async () => {
  await assert.rejects(
    runProcess({
      executable: "node.exe",
      args: [],
      cwd: CWD,
      env: {},
      timeoutMs: 1000,
    }),
    /executable must be an absolute path/,
  );

  await assert.rejects(
    runProcess({
      executable: process.execPath,
      args: [],
      cwd: ".",
      env: {},
      timeoutMs: 1000,
    }),
    /cwd must be an absolute path/,
  );
});
