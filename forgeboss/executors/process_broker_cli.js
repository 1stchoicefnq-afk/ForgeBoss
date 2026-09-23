"use strict";

const { runProcess } = require("./process_broker");

const MAX_STDIN_BYTES = 2 * 1024 * 1024;
const ALLOWED_KEYS = new Set([
  "schema",
  "executable",
  "args",
  "cwd",
  "env",
  "timeoutMs",
  "maxOutput",
]);

function fail(error, code = 2) {
  const payload = {
    schema: 1,
    ok: false,
    error: {
      name: error && error.name ? String(error.name) : "Error",
      message: error && error.message ? String(error.message) : String(error),
    },
  };
  process.stdout.write(JSON.stringify(payload) + "\n");
  process.exitCode = code;
}

async function readRequest() {
  let total = 0;
  const chunks = [];
  for await (const raw of process.stdin) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    total += chunk.length;
    if (total > MAX_STDIN_BYTES) {
      throw new Error("broker request exceeds stdin byte cap");
    }
    chunks.push(chunk);
  }
  if (total === 0) throw new Error("broker request is empty");
  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
  } catch {
    throw new Error("broker request is not valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("broker request root must be an object");
  }
  if (!Number.isInteger(value.schema) || value.schema !== 1) {
    throw new Error("unsupported broker request schema");
  }
  const extra = Object.keys(value).filter((key) => !ALLOWED_KEYS.has(key));
  if (extra.length) {
    throw new Error("unexpected broker request keys: " + extra.sort().join(","));
  }
  const { schema, ...request } = value;
  return request;
}

async function main() {
  let request;
  try {
    request = await readRequest();
  } catch (error) {
    fail(error, 2);
    return;
  }

  let result;
  try {
    result = await runProcess(request);
  } catch (error) {
    fail(error, 3);
    return;
  }

  const payload = { schema: 1, ok: true, result };
  process.stdout.write(JSON.stringify(payload) + "\n");

  if (result.startError) {
    process.exitCode = 4;
  } else if (result.cleanupOk !== true) {
    process.exitCode = 13;
  } else {
    process.exitCode = 0;
  }
}

main().catch((error) => fail(error, 2));
