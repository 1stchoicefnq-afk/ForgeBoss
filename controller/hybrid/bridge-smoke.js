'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const { route } = require('./model-router');
const { GuardedCodingTools, SecurityDenial } = require('./coding-tools');

let pass = 0, fail = 0;
function ok(name, value, detail = '') {
  console.log(`[${value ? 'PASS' : 'FAIL'}] ${name}${detail ? ': ' + detail : ''}`);
  value ? pass++ : fail++;
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'siteboss-hybrid-'));
try {
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'tests'), { recursive: true });

  fs.writeFileSync(
    path.join(root, 'src', 'math.js'),
    "function add(a,b){ return a-b; }\nmodule.exports={add};\n",
    'utf8'
  );
  fs.writeFileSync(
    path.join(root, 'src', 'secret.js'),
    "module.exports='do-not-touch';\n",
    'utf8'
  );
  fs.writeFileSync(
    path.join(root, 'tests', 'math.test.js'),
    "const {add}=require('../src/math');\nif(add(2,3)!==5){process.exit(2)}\nconsole.log('PASS');\n",
    'utf8'
  );

  const packet = {
    packet_id: 'SB-HYBRID-SMOKE-001',
    objective: 'Fix a simple arithmetic implementation bug.',
    expected_head_revision: 'fixture-head',
    context_files: ['src/math.js', 'tests/math.test.js'],
    allowed_files: ['src/math.js'],
    required_tests: [['node', 'tests/math.test.js']]
  };

  const routing = route(packet, {
    local: { enabled: true, endpoint: 'http://127.0.0.1:11434/v1' }
  });
  ok('simple bounded task routes local-capable', routing.provider === 'local', routing.provider);

  const tools = new GuardedCodingTools(root, packet);
  ok('allowed source readable', tools.read('src/math.js').includes('a-b'));

  let denied = false;
  try { tools.read('src/secret.js'); } catch (e) { denied = e instanceof SecurityDenial; }
  ok('unauthorized read blocked', denied);

  denied = false;
  try { tools.editExact('src/secret.js', 'do-not-touch', 'changed'); } catch (e) { denied = e instanceof SecurityDenial; }
  ok('unauthorized write blocked', denied);

  denied = false;
  try { tools.editExact('../outside.txt', 'a', 'b'); } catch (e) { denied = e instanceof SecurityDenial; }
  ok('traversal blocked', denied);

  denied = false;
  try { tools.editExact('C:\\outside\\x.js', 'a', 'b'); } catch (e) { denied = e instanceof SecurityDenial; }
  ok('Windows absolute path blocked', denied);

  tools.editExact(
    'src/math.js',
    'function add(a,b){ return a-b; }',
    'function add(a,b){ return a+b; }'
  );
  ok('authorized exact edit succeeds', tools.read('src/math.js').includes('a+b'));

  const test = cp.spawnSync(process.execPath, ['tests/math.test.js'], {
    cwd: root,
    encoding: 'utf8',
    shell: false
  });
  ok('approved fixture test passes', test.status === 0, (test.stdout + test.stderr).trim());

  const evidence = {
    schema: 1,
    packet_id: packet.packet_id,
    route: routing,
    files_changed: [...tools.modified],
    tests: [{ argv: [process.execPath, 'tests/math.test.js'], exit_code: test.status }],
    scope_respected: true,
    write_authority_respected: true,
    github_writes: 0,
    model_calls: 0
  };

  ok('only authorized file changed',
    evidence.files_changed.length === 1 && evidence.files_changed[0] === 'src/math.js');

  const outDir = path.resolve(__dirname, '..', '..', 'state', 'hybrid');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'bridge-smoke-last.json'), JSON.stringify(evidence, null, 2));

  console.log(`HYBRID BRIDGE SMOKE COMPLETE: PASS=${pass} FAIL=${fail}`);
  process.exitCode = fail ? 2 : 0;
} finally {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
}
