/**
 * Local audit log of guard decisions, so users can see what the agent tried and tune policy.
 *
 * Stored inside the Git directory (.git/safepush/audit.jsonl), which is never committed or
 * pushed. Entries hold the event, tool, decision and guard name only: no paths, commands,
 * prompts or matched values. Rotated at MAX_BYTES. Failures are silent: logging must never
 * change a security decision. Read with `safepush log`.
 */
import { appendFileSync, mkdirSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { gitExec } from './git.mjs';
const MAX_BYTES = 1_000_000;
export function audit(repoRoot, entry) {
    if (!repoRoot)
        return;
    try {
        const gitDir = String(gitExec(repoRoot, ['rev-parse', '--absolute-git-dir'], { encoding: 'utf8' })).trim();
        const dir = join(gitDir, 'safepush');
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = join(dir, 'audit.jsonl');
        try {
            if (statSync(file).size > MAX_BYTES)
                renameSync(file, file + '.1');
        }
        catch { /* first write */ }
        const safe = Object.fromEntries(Object.entries(entry).map(([k, v]) => [k, String(v).slice(0, 80).replace(/[^\w.:/ -]/g, '?')]));
        appendFileSync(file, JSON.stringify({ time: new Date().toISOString(), ...safe }) + '\n', { mode: 0o600 });
    }
    catch { /* never affect the decision */ }
}
