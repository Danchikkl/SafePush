import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { gitExec, gitRoot, listGitFiles, listLocalFiles, safeFile, trackedFiles } from './git.mjs';
import { envIgnoreMissing, finding, isEnvFile, isEnvTemplate, scanContent } from './rules.mjs';
import { addEvidence, priorityOrder } from './evidence.mjs';
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 10_000;
const skipExtensions = /\.(?:png|jpe?g|gif|webp|pdf|zip|gz|7z|mp3|mp4|woff2?|ico|lock)$/i;
function isBinary(data) {
    return data.subarray(0, 8192).includes(0);
}
function readStaged(root, file) {
    // Check the object size BEFORE reading; don't silently swallow Git read failures.
    const size = Number(String(gitExec(root, ['cat-file', '-s', ':' + file], { encoding: 'utf8' })).trim());
    if (!Number.isSafeInteger(size) || size < 0)
        throw new Error('Cannot determine size of a staged file.');
    if (size > MAX_FILE_BYTES)
        return null;
    return Buffer.from(gitExec(root, ['show', ':' + file]));
}
function frameworks(root) {
    const p = safeFile(root, 'package.json');
    if (!p)
        return [];
    try {
        const pkg = JSON.parse(readFileSync(p, 'utf8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        return [deps.next ? 'Next.js' : null, deps.vite ? 'Vite' : null, deps['react-scripts'] ? 'Create React App' : null].filter((v) => Boolean(v));
    }
    catch {
        return [];
    }
}
export function scan(options) {
    const requestedRoot = resolve(options.root);
    const repoRoot = gitRoot(requestedRoot);
    const root = repoRoot ?? requestedRoot;
    if (options.staged && !repoRoot)
        throw new Error('Staged scans require a Git repository.');
    const entries = repoRoot ? listGitFiles(root, Boolean(options.staged)) : listLocalFiles(root);
    if (entries.length > MAX_FILES)
        throw new Error('Scan stopped: more than ' + MAX_FILES + ' files.');
    const tracked = repoRoot ? trackedFiles(root) : new Set();
    const findings = [];
    let filesScanned = 0;
    let skippedLargeOrBinary = 0;
    for (const file of entries) {
        if (skipExtensions.test(file))
            continue;
        let contents;
        if (options.staged) {
            const staged = readStaged(root, file);
            if (!staged) {
                skippedLargeOrBinary++;
                continue;
            }
            contents = staged;
        }
        else {
            const full = safeFile(root, file);
            if (!full)
                continue;
            if (statSync(full).size > MAX_FILE_BYTES) {
                skippedLargeOrBinary++;
                continue;
            }
            contents = readFileSync(full);
        }
        if (contents.length > MAX_FILE_BYTES || isBinary(contents)) {
            skippedLargeOrBinary++;
            continue;
        }
        filesScanned++;
        findings.push(...scanContent(file.replaceAll('\\', '/'), contents.toString('utf8')));
    }
    // Even if an env file is unchanged, it is still at risk while tracked.
    for (const candidate of tracked) {
        const relativeFile = candidate.replaceAll('\\', '/');
        if (isEnvFile(relativeFile) && !isEnvTemplate(relativeFile)) {
            findings.push(finding('TRACKED_ENV_FILE', 'high', relativeFile, undefined, 'Environment file is present in the Git index', 'A non-template .env file is tracked or staged in Git, potentially exposing its contents.', 'If pushed or exposed, revoke/rotate credentials first. Add .gitignore rules, then use git rm --cached -- <filename> to stop tracking without deleting the local file. Old commits still contain the file.'));
        }
    }
    if (!options.staged && safeFile(root, 'package.json')) {
        const ignoreFile = safeFile(root, '.gitignore');
        const ignoreText = ignoreFile ? readFileSync(ignoreFile, 'utf8') : '';
        if (envIgnoreMissing(ignoreText)) {
            findings.push(finding('ENV_GITIGNORE_MISSING', 'medium', '.gitignore', undefined, 'Environment files are not clearly ignored', 'Your .gitignore does not contain standard .env and .env.* patterns. This is a heuristic.', 'Run safepush init. Existing tracked files require git rm --cached.'));
        }
    }
    if (options.staged && skippedLargeOrBinary > 0) {
        throw new Error('Incomplete staged scan: ' + skippedLargeOrBinary + ' oversized or binary file(s) could not be checked. Review before committing.');
    }
    const mode = options.staged ? 'staged' : 'workspace';
    const reviewed = findings.map(f => addEvidence(f, mode));
    reviewed.sort((a, b) => priorityOrder(a.priority) - priorityOrder(b.priority) || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
    return { root, mode, filesScanned, frameworks: frameworks(root), findings: reviewed, skippedLargeOrBinary };
}
