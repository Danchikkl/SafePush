import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,readFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {scan} from '../dist/scanner.mjs';

const executable=join(dirname(fileURLToPath(import.meta.url)),'..','dist','cli.mjs');
function run(args,cwd){return spawnSync(process.execPath,[executable,...args],{cwd,encoding:'utf8',timeout:15000});}
function git(args,cwd){const p=spawnSync('git',args,{cwd,encoding:'utf8'});if(p.status)throw new Error(p.stderr);return p.stdout;}
function sandbox(fn){const dir=mkdtempSync(join(tmpdir(),'safepush-'));try{fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}}
function fakeGithubToken(){return 'ghp_'+'A1b2C3d4E5f6G7h8I9j0'.repeat(2);}
function requireNoFile(path){try{readFileSync(path);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}}
test('detects token without printing its value',()=>sandbox(dir=>{
 const token=fakeGithubToken();writeFileSync(join(dir,'app.js'),'const token = "'+token+'";\n');
 const result=run(['scan','.','--json'],dir);assert.equal(result.status,1,result.stderr);
 assert.ok(!result.stdout.includes(token));assert.ok(JSON.parse(result.stdout).findings.some(f=>f.rule==='KNOWN_SECRET'));
}));
test('warns about browser-exposed secret-looking names',()=>sandbox(dir=>{
 writeFileSync(join(dir,'web.js'),'console.log(import.meta.env.VITE_ADMIN_SECRET);\n');
 assert.ok(scan({root:dir}).findings.some(f=>f.rule==='CLIENT_EXPOSED_SECRET_NAME'));
}));
test('placeholders are not hardcoded secrets',()=>sandbox(dir=>{
 writeFileSync(join(dir,'.env.example'),'API_KEY=your_api_key_here\n');
 assert.equal(scan({root:dir}).findings.length,0);
}));
test('init adds env ignore patterns idempotently',()=>sandbox(dir=>{
 writeFileSync(join(dir,'.gitignore'),'node_modules/\n');assert.equal(run(['init'],dir).status,0);
 const old=readFileSync(join(dir,'.gitignore'),'utf8');assert.ok(old.includes('.env.*'));
 assert.equal(run(['init'],dir).status,0);assert.equal(readFileSync(join(dir,'.gitignore'),'utf8'),old);
}));
test('tracked .env triggers a finding',()=>sandbox(dir=>{
 git(['init','-q'],dir);writeFileSync(join(dir,'.env'),'SERVICE_URL=https://example.test\n');git(['add','-f','.env'],dir);
 assert.ok(scan({root:dir}).findings.some(f=>f.rule==='TRACKED_ENV_FILE'));
}));
test('untracked .env is not called tracked',()=>sandbox(dir=>{
 writeFileSync(join(dir,'.env'),'MODE=dev\n');assert.ok(!scan({root:dir}).findings.some(f=>f.rule==='TRACKED_ENV_FILE'));
}));
test('tracked .env remains flagged when deleted only from worktree',()=>sandbox(dir=>{
 git(['init','-q'],dir);writeFileSync(join(dir,'.env'),'MODE=dev\n');git(['add','-f','.env'],dir);rmSync(join(dir,'.env'));
 assert.ok(scan({root:dir}).findings.some(f=>f.rule==='TRACKED_ENV_FILE'));
}));
test('staged mode uses Git index, not mutable worktree',()=>sandbox(dir=>{
 git(['init','-q'],dir);const token=fakeGithubToken();writeFileSync(join(dir,'app.js'),"const token = '"+token+"';\n");
 git(['add','app.js'],dir);writeFileSync(join(dir,'app.js'),'console.log("replaced only in working tree");\n');
 const staged=run(['scan','--staged','--json'],dir);assert.equal(staged.status,1,staged.stderr);
 assert.ok(JSON.parse(staged.stdout).findings.some(f=>f.rule==='KNOWN_SECRET'));assert.ok(!staged.stdout.includes(token));
}));
test('existing hook is untouched',()=>sandbox(dir=>{
 git(['init','-q'],dir);const hook=join(dir,'.git','hooks','pre-commit');
 writeFileSync(hook,'#!/bin/sh\necho existing\n');
 assert.equal(run(['init','--hook'],dir).status,0);
 assert.equal(readFileSync(hook,'utf8'),'#!/bin/sh\necho existing\n');
}));
test('does not follow file symlink outside scan root',()=>sandbox(dir=>{
 const outer=mkdtempSync(join(tmpdir(),'safepush-outer-'));
 try{writeFileSync(join(dir,'safe.txt'),'hello');writeFileSync(join(outer,'secret.txt'),fakeGithubToken());
 symlinkSync(join(outer,'secret.txt'),join(dir,'link.txt'));
 const r=scan({root:dir});assert.equal(r.filesScanned,1);assert.equal(r.findings.length,0);
 }finally{rmSync(outer,{recursive:true,force:true});}
}));
test('explain works; bad flags fail',()=>sandbox(dir=>{
 assert.equal(run(['explain','TRACKED_ENV_FILE'],dir).status,0);
 assert.equal(run(['scan','--nonsense'],dir).status,2);
}));
test('does not traverse symlinked directories',()=>sandbox(dir=>{
 const outer=mkdtempSync(join(tmpdir(),'safepush-outer-'));
 try{writeFileSync(join(outer,'secret.js'),fakeGithubToken());
 symlinkSync(outer,join(dir,'linked-directory'),'dir');
 const r=scan({root:dir});assert.equal(r.filesScanned,0);assert.equal(r.findings.length,0);
 }finally{rmSync(outer,{recursive:true,force:true});}
}));
test('init refuses symlinked .gitignore outside root',()=>sandbox(dir=>{
 const outer=mkdtempSync(join(tmpdir(),'safepush-outer-'));
 try{const target=join(outer,'settings');writeFileSync(target,'PRESERVE_ME\n');
 symlinkSync(target,join(dir,'.gitignore'));assert.equal(run(['init'],dir).status,2);
 assert.equal(readFileSync(target,'utf8'),'PRESERVE_ME\n');
 }finally{rmSync(outer,{recursive:true,force:true});}
}));
test('custom core.hooksPath is never modified',()=>sandbox(dir=>{
 const outer=mkdtempSync(join(tmpdir(),'safepush-hooks-'));
 try{git(['init','-q'],dir);git(['config','--local','core.hooksPath',outer],dir);
 const result=run(['init','--hook'],dir);assert.equal(result.status,2);
 assert.match(result.stderr,/Custom core\.hooksPath/);
 assert.equal(requireNoFile(join(outer,'pre-commit')),false);
 assert.equal(requireNoFile(join(dir,'.gitignore')),false);
 }finally{rmSync(outer,{recursive:true,force:true});}
}));
test('staged mode fails closed on oversized changed file',()=>sandbox(dir=>{
 git(['init','-q'],dir);writeFileSync(join(dir,'large.js'),'a'.repeat(1_000_001));git(['add','large.js'],dir);
 const r=run(['scan','--staged','--json'],dir);
 assert.equal(r.status,2);assert.match(r.stderr,/Incomplete staged scan/);
}));
test('token-shaped filenames are redacted in both reports',()=>sandbox(dir=>{
 const token=fakeGithubToken();writeFileSync(join(dir,'file-'+token+'.js'),"const token='"+token+"';");
 for(const flags of [[],['--json']]){const r=run(['scan',...flags],dir);
 assert.equal(r.status,1);assert.ok(!r.stdout.includes(token));assert.ok(r.stdout.includes('[REDACTED]'));}
}));
test('symlinked metadata is not read from outside root',()=>sandbox(dir=>{
 const outer=mkdtempSync(join(tmpdir(),'safepush-foreign-'));
 try{writeFileSync(join(outer,'package.json'),JSON.stringify({dependencies:{next:'15.0.0'}}));
 writeFileSync(join(outer,'.gitignore'),'.env\n.env.*\n');
 symlinkSync(join(outer,'package.json'),join(dir,'package.json'));
 symlinkSync(join(outer,'.gitignore'),join(dir,'.gitignore'));
 const r=scan({root:dir});assert.deepEqual(r.frameworks,[]);assert.equal(r.filesScanned,0);
 }finally{rmSync(outer,{recursive:true,force:true});}
}));
test('normal opt-in hook installs',()=>sandbox(dir=>{
 git(['init','-q'],dir);const r=run(['init','--hook'],dir);assert.equal(r.status,0,r.stderr);
 assert.match(readFileSync(join(dir,'.git','hooks','pre-commit'),'utf8'),/safepush scan --staged/);
}));
test('init repairs negated .env rules and is idempotent',()=>sandbox(dir=>{
 writeFileSync(join(dir,'.gitignore'),'.env\n.env.*\n!.env\n!.env.*\n');
 assert.equal(run(['init'],dir).status,0);
 const fixed=readFileSync(join(dir,'.gitignore'),'utf8');assert.match(fixed,/SafePush: keep real environment files/);
 assert.equal(run(['init'],dir).status,0);assert.equal(readFileSync(join(dir,'.gitignore'),'utf8'),fixed);
}));
test('staged scan catches unchanged tracked .env',()=>sandbox(dir=>{
 git(['init','-q'],dir);writeFileSync(join(dir,'.env'),'DB_PASSWORD=example\n');git(['add','.env'],dir);
 git(['-c','user.name=Example','-c','user.email=example@invalid.test','commit','-qm','fixture'],dir);
 writeFileSync(join(dir,'safe.js'),'export const ok=true;\n');git(['add','safe.js'],dir);
 const r=run(['scan','--staged','--json'],dir);assert.equal(r.status,1,r.stderr);
 assert.ok(JSON.parse(r.stdout).findings.some(f=>f.rule==='TRACKED_ENV_FILE'&&f.file==='.env'));
}));
