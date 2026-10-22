#!/usr/bin/env node
// Copies the compiled CLI and MCP server into plugin/dist so the Claude Code plugin works
// straight from a Git checkout, without npm. SafePush has no runtime dependencies, so the
// compiled files are the whole program. CI rebuilds this folder and fails if it differs
// from what is committed, so the bundled code always matches src/.
import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const from = join(root, 'dist');
const to = join(root, 'plugin', 'dist');
rmSync(to, { recursive: true, force: true });
mkdirSync(to, { recursive: true });
// Only modules that exist in src/: a stale dist/ (e.g. after switching branches) must not leak in.
const files = readdirSync(join(root, 'src')).filter(name => name.endsWith('.mts')).map(name => name.replace(/\.mts$/, '.mjs')).sort();
for (const name of files) if (!existsSync(join(from, name))) throw new Error('Missing dist/' + name + '. Run npm run build first.');
if (!files.includes('cli.mjs') || !files.includes('mcp.mjs')) throw new Error('Run npm run build first.');
for (const name of files) copyFileSync(join(from, name), join(to, name));
copyFileSync(join(root, 'LICENSE'), join(root, 'plugin', 'LICENSE'));
console.log('plugin/dist: ' + files.length + ' files');
