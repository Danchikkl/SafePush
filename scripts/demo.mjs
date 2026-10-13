import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const root = mkdtempSync(join(tmpdir(), 'safepush-demo-'));
const cli = new URL('../dist/cli.mjs', import.meta.url).pathname;
function run() {
  const result = spawnSync(process.execPath, [cli, 'scan', root], {encoding:'utf8'});
  console.log(result.stdout);
  if (result.stderr) console.error(result.stderr);
}
try {
  mkdirSync(join(root,'src'));
  writeFileSync(join(root,'package.json'), JSON.stringify({dependencies:{next:'15.0.0'}}));
  writeFileSync(join(root,'src','app.js'), 'const key = "ghp_" + "DUMMY";\nconst test = "ghp_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2) + '";\nconsole.log(process.env.NEXT_PUBLIC_ADMIN_SECRET);\n');
  console.log('Before fixes (synthetic credentials only):');
  run();
  writeFileSync(join(root,'src','app.js'), 'console.log("hello world");\n');
  writeFileSync(join(root,'.gitignore'), '.env\n.env.*\n');
  console.log('After manual fix:');
  run();
} finally { rmSync(root, {recursive:true,force:true}); }
