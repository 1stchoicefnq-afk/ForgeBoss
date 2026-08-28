"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const command = process.platform === "win32" ? "cline.cmd" : "cline";
const result = spawnSync(command, ["--version"], {
  encoding: "utf8",
  shell: false,
  windowsHide: true,
  timeout: 30000,
});

const ok = !result.error && result.status === 0;
const detail = (result.stdout || result.stderr || result.error?.message || "").trim();
console.log(`[${ok ? "PASS" : "FAIL"}] Cline: ${detail}`);

const dir = path.join(os.homedir(), ".forgeboss", "runtime");
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "cline-version.txt"), detail);

process.exit(ok ? 0 : 2);
