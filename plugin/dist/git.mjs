import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, lstatSync, realpathSync } from 'node:fs';
import { join, relative, resolve, isAbsolute, sep } from 'node:path';
export function gitExec(root, args, opts) {
    return execFileSync('git', ['-C', root, ...args], {
        encoding: opts?.encoding ?? 'buffer',
        maxBuffer: 32 * 1024 * 1024,
        timeout: 20_000,
        stdio: ['ignore', 'pipe', 'pipe'],
    });
}
export function gitRoot(path) {
    try {
        return String(gitExec(path, ['rev-parse', '--show-toplevel'], { encoding: 'utf8' })).trim();
    }
    catch {
        return null;
    }
}
function splitNull(input) {
    return Buffer.from(input).toString('utf8').split('\0').filter(Boolean);
}
export function trackedFiles(root) {
    return new Set(splitNull(gitExec(root, ['ls-files', '--cached', '-z'])));
}
export function listGitFiles(root, staged) {
    const args = staged
        ? ['diff', '--cached', '--name-only', '-z', '--no-ext-diff', '--diff-filter=ACMRT']
        : ['ls-files', '--cached', '--others', '--exclude-standard', '-z'];
    return splitNull(gitExec(root, args));
}
const ignoredDirectories = new Set([
    '.git', 'node_modules', 'dist', 'build', '.next', '.nuxt', '.output',
    'coverage', '.turbo', '.svelte-kit', '.venv', 'venv', '__pycache__',
]);
export function listLocalFiles(root, maxFiles = 10_000) {
    const paths = [];
    const visit = (dir) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
            if (entry.isSymbolicLink())
                continue;
            const full = join(dir, entry.name);
            if (entry.isDirectory()) {
                if (!ignoredDirectories.has(entry.name))
                    visit(full);
            }
            else if (entry.isFile()) {
                paths.push(relative(root, full));
                if (paths.length > maxFiles)
                    throw new Error('Scan stopped: too many files. Scan a smaller directory.');
            }
        }
    };
    visit(root);
    return paths;
}
export function safeFile(root, relativePath) {
    const target = resolve(root, relativePath);
    const normalizedRoot = resolve(root);
    const fromRoot = relative(normalizedRoot, target);
    if (fromRoot === '..' || fromRoot.startsWith('..' + sep) || isAbsolute(fromRoot))
        return null;
    if (!existsSync(target))
        return null;
    try {
        if (!lstatSync(target).isFile())
            return null;
        const realRoot = realpathSync(normalizedRoot);
        const realTarget = realpathSync(target);
        const physicalRelative = relative(realRoot, realTarget);
        if (physicalRelative === '..' || physicalRelative.startsWith('..' + sep) || isAbsolute(physicalRelative))
            return null;
        return realTarget;
    }
    catch {
        return null;
    }
}
