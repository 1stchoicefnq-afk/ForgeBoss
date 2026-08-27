"use strict";

const assert = require("assert");
const { spawnSync } = require("child_process");
const path = require("path");

const runner = path.resolve(__dirname, "..", "executors", "cline_runner.js");

function run(extraEnv) {
  return spawnSync(process.execPath, [runner, "missing-packet.json", "."], {
    encoding: "utf8",
    env: { ...process.env, ...extraEnv },
    shell: false,
    windowsHide: true,
    timeout: 30000,
  });
}

let result = run({
  FORGEBOSS_ALLOW_PAID_EXECUTOR: "",
  FORGEBOSS_ENABLE_QUARANTINED_CLINE: "",
  FORGEBOSS_OS_ISOLATION_VERIFIED: "",
});
assert.strictEqual(result.status, 3);
assert.match(result.stderr, /paid executor gate disabled/i);

result = run({
  FORGEBOSS_ALLOW_PAID_EXECUTOR: "YES",
  FORGEBOSS_ENABLE_QUARANTINED_CLINE: "",
  FORGEBOSS_OS_ISOLATION_VERIFIED: "YES",
});
assert.strictEqual(result.status, 13);
assert.match(result.stderr, /QUARANTINED/i);

result = run({
  FORGEBOSS_ALLOW_PAID_EXECUTOR: "YES",
  FORGEBOSS_ENABLE_QUARANTINED_CLINE: "YES",
  FORGEBOSS_OS_ISOLATION_VERIFIED: "",
});
assert.strictEqual(result.status, 13);
assert.match(result.stderr, /verified OS\/network isolation/i);

console.log("[PASS] Cline runner gates fail closed before packet or CLI execution.");
