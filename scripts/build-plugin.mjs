#!/usr/bin/env node
// Copies the compiled CLI and MCP server into plugin/dist so the Claude Code plugin works
// straight from a Git checkout, without npm. SafePush has no runtime dependencies, so the
// compiled files are the whole program. CI rebuilds this folder and fails if it differs
// from what is committed, so the bundled code always matches src/.
import { copyFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const from = join(root, 'dist');
const to = join(root, 'plugin', 'dist');
rmSync(to, { recursive: true, force: true });
mkdirSync(to, { recursive: true });
const files = readdirSync(from).filter(name => name.endsWith('.mjs')).sort();
if (!files.includes('cli.mjs') || !files.includes('mcp.mjs')) throw new Error('Run npm run build first.');
for (const name of files) copyFileSync(join(from, name), join(to, name));
copyFileSync(join(root, 'LICENSE'), join(root, 'plugin', 'LICENSE'));
console.log('plugin/dist: ' + files.length + ' files');
