/**
 * Agent network policy: what code the agent pulls in, and which sites it scrapes.
 *
 * Supply chain (ask): code fetched from the internet that runs on the user's machine with
 * access to every local secret.
 *   - pipe-to-shell         curl … | sh, bash <(curl …), iex (irm …)
 *   - install from git      npm i github:u/r, pip install git+https://…, npx u/r, cargo install --git
 *   - clone and run         git clone … && npm install / make / ./install.sh
 *   - release binaries      …/releases/download/… + chmod +x / run
 *   - lookalike packages    npm i reqeusts-style names one edit away from a popular package
 *   - git dependencies      a manifest or MCP config gets an unpinned git/GitHub dependency
 *
 * Scraping (ask / deny): legal risk usually starts with getting around a site's protection.
 *   - blocked domains       policy.network.blockedDomains → deny for WebFetch, curl/wget, MCP args
 *   - crawler MCP tools     mcp__*crawl* / *scrap* / *spider* → ask
 *   - anti-bot evasion      stealth plugins, CAPTCHA solvers, cloudscraper → ask
 *
 * Everything is textual and local: no network calls, no package registry lookups.
 * policy.network.trustedSources silences supply-chain asks for listed GitHub owners or hosts.
 */
import { basename } from 'node:path';
import type { Finding } from './types.mjs';
import { finding } from './rules.mjs';

type Json = Record<string, unknown>;
const isRecord = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
export type NetDecision = { decision: 'deny' | 'ask'; reason: string } | null;

export interface NetworkPolicy {
  /** "github.com/owner/*", "github.com/owner/repo", or a host such as "bun.sh" / "*.example.com". */
  trustedSources: string[];
  /** Hosts the agent must never fetch or scrape: "linkedin.com", "*.gov.kz". */
  blockedDomains: string[];
}

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

/* ------------------------------------------------------------------ sources and trust */

/** GitHub owner/repo references and hosts mentioned in a command or text. */
export function sourcesIn(text: string): { github: string[]; hosts: string[] } {
  const github = new Set<string>();
  for (const re of [
    /\bgithub\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?=[/#\s"'`)]|$)/gi,
    /\braw\.githubusercontent\.com\/([\w.-]+)\/([\w.-]+)/gi,
    /\bgithub:([\w.-]+)\/([\w.-]+?)(?=[#\s"'`)]|$)/gi,
  ]) for (const m of text.matchAll(re)) github.add((m[1] + '/' + m[2]).toLowerCase());
  for (const m of text.matchAll(/\bgist\.github(?:usercontent)?\.com\/([\w.-]+)/gi)) github.add(m[1].toLowerCase() + '/*gist');
  const hosts = new Set<string>();
  for (const m of text.matchAll(/\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)) hosts.add(m[1].toLowerCase());
  return { github: [...github], hosts: [...hosts] };
}

function hostMatches(host: string, pattern: string): boolean {
  const p = pattern.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (p.startsWith('*.')) return host === p.slice(2) || host.endsWith(p.slice(1));
  return host === p || host.endsWith('.' + p);
}

function trusted(policy: NetworkPolicy, src: { github: string[]; hosts: string[] }): boolean {
  if (!src.github.length && !src.hosts.length) return false;
  const gh = policy.trustedSources.map(t => t.toLowerCase().replace(/^https?:\/\//, ''))
    .filter(t => t.startsWith('github.com/')).map(t => t.slice('github.com/'.length));
  const githubOk = src.github.every(ref => gh.some(t => t === ref || (t.endsWith('/*') && ref.startsWith(t.slice(0, -1)))));
  const hostsOk = src.hosts
    .filter(h => !/^(?:github\.com|raw\.githubusercontent\.com|objects\.githubusercontent\.com|codeload\.github\.com|gist\.github(?:usercontent)?\.com)$/.test(h) || !src.github.length)
    .every(h => policy.trustedSources.some(t => !t.toLowerCase().startsWith('github.com/') && hostMatches(h, t)));
  return githubOk && hostsOk;
}

function where(src: { github: string[]; hosts: string[] }): string {
  const all = [...src.github.map(g => 'github.com/' + g.replace('/*gist', ' (gist)')), ...src.hosts.filter(h => !/github/.test(h))];
  return all.length ? ' (' + all.slice(0, 3).join(', ') + ')' : '';
}

/* ------------------------------------------------------------------ supply chain */

const AT_CMD = String.raw`(?:^|[;&|(\x60]\s*|\$\(\s*)(?:sudo\s+)?`;
const fetcher = String.raw`(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|fetch)`;
const shell = String.raw`(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|Invoke-Expression`;
const pipeToShell = new RegExp(
  String.raw`\b${fetcher}\b[^|;&]*\|\s*(?:${shell})\b` +            // curl … | sh
  String.raw`|\b(?:${shell})\s+(?:-\S+\s+)*<\(\s*${fetcher}\b` +       // bash <(curl …)
  String.raw`|\b(?:${shell})\s+-c\s+["']?\$\(\s*${fetcher}\b` +        // sh -c "$(curl …)"
  String.raw`|\b(?:iex|Invoke-Expression)\s*\(?\s*(?:\(?\s*)?${fetcher}\b`, 'i');  // iex (irm …)

const nodeInstall = new RegExp(AT_CMD + String.raw`(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b([^;&|]*)`, 'i');
const npxRun = new RegExp(AT_CMD + String.raw`(?:npx|pnpm\s+dlx|bunx|yarn\s+dlx)\b([^;&|]*)`, 'i');
const pipInstall = new RegExp(AT_CMD + String.raw`(?:(?:python[0-9.]*\s+-m\s+)?pip[0-9.]*|uv\s+pip|pipx)\s+install\b([^;&|]*)`, 'i');
const gitSpec = /(?:^|\s)(?:github:|gitlab:|bitbucket:|git\+|git:\/\/|https?:\/\/(?:www\.)?github\.com\/|https?:\/\/gist\.github)/i;
// npm/npx shorthand "owner/repo" (not a scope, not a path, not a URL).
const bareRepo = /(?:^|\s)(?!@|\.|\/|-)[A-Za-z0-9][\w.-]*\/[\w.-]+(?:#\S+)?(?=\s|$)/;
const archiveInstall = /(?:^|\s)https?:\/\/\S+\.(?:whl|tar\.gz|tgz|zip)(?=\s|$)/i;
const otherGitInstall = /\bcargo\s+install\b[^;&|]*--git\b|\buvx\s+--from\s+git\+|\bgem\s+install\b[^;&|]*--source\b|\bgo\s+run\s+\S+@/i;
const cloneThenRun = new RegExp(String.raw`\bgit\s+clone\b[^;&|]*(?:&&|;)(?:\s*cd\s+\S+\s*(?:&&|;))?\s*(?:sudo\s+)?(?:(?:npm|pnpm|yarn|bun)\s+(?:i|install|ci|run|start)\b|make\b|cmake\b|\.\/\S+|(?:ba|z)?sh\s+\S+|python[0-9.]*\s+\S+\.py|pip[0-9.]*\s+install|go\s+run|cargo\s+(?:run|build))`, 'i');
const releaseBinary = /\b(?:github\.com\/[\w.-]+\/[\w.-]+\/releases\/download\/|objects\.githubusercontent\.com\/)[^;&|]*(?:&&|;|\|)[^;&|]*(?:\bchmod\s+\+?[0-7]*x|\.\/[\w.-]+|\bsudo\s+(?:mv|cp|install)\b|\btar\s+-?x)/i;

// A short, fixed list of popular package names: a name one edit away from one of these is a
// common typosquat shape. Legitimate neighbours are listed so they never ask.
const POPULAR: Record<'npm' | 'pip', string[]> = {
  npm: ['react', 'react-dom', 'lodash', 'express', 'axios', 'typescript', 'webpack', 'eslint', 'prettier',
    'moment', 'dotenv', 'chalk', 'commander', 'mongoose', 'body-parser', 'jsonwebtoken', 'bcrypt', 'nodemon',
    'socket.io', 'redux', 'tailwindcss', 'prisma', 'openai', 'nodemailer', 'puppeteer', 'playwright',
    'cross-env', 'node-fetch', 'yargs', 'inquirer', 'electron', 'supabase', 'stripe', 'firebase'],
  pip: ['requests', 'numpy', 'pandas', 'flask', 'django', 'fastapi', 'pydantic', 'sqlalchemy', 'pytest',
    'matplotlib', 'scipy', 'boto3', 'openai', 'anthropic', 'torch', 'tensorflow', 'beautifulsoup4',
    'selenium', 'pillow', 'urllib3', 'setuptools', 'colorama', 'python-dotenv', 'httpx', 'uvicorn',
    'scikit-learn', 'transformers', 'langchain', 'cryptography', 'pyyaml'],
};
const LEGIT_NEIGHBOURS = new Set(['preact', 'colors', 'color', 'request', 'redox', 'moments', 'expresso',
  'chalk-template', 'electron-builder', 'prism', 'yarg', 'pillow-heif', 'pandas-ta', 'flasgger', 'httpie',
  'torchx', 'scipy-stubs']);

function oneEditApart(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diff = [...a].map((c, i) => (c === b[i] ? -1 : i)).filter(i => i >= 0);
    if (diff.length === 1) return true;
    return diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]];
  }
  const [s, l] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < l.length; i++) if (l.slice(0, i) + l.slice(i + 1) === s) return true;
  return false;
}
const normalizePip = (n: string) => n.toLowerCase().replace(/[-_.]+/g, '-');

/** Package names in an install command's argument list (flags and versions stripped). */
function packageNames(args: string, eco: 'npm' | 'pip'): string[] {
  return args.split(/\s+/).filter(t => t && !t.startsWith('-') && !t.includes('/') && !t.includes(':'))
    .map(t => t.replace(/^['"]|['"]$/g, ''))
    .map(t => (eco === 'npm' ? t.replace(/(?!^)@.*$/, '') : normalizePip(t.replace(/[<>=!~;\[].*$/, ''))))
    .filter(t => /^[a-z0-9][\w.-]*$/i.test(t));
}

export function lookalikePackage(command: string): { name: string; like: string } | null {
  for (const [re, eco] of [[nodeInstall, 'npm'], [pipInstall, 'pip']] as const) {
    const m = re.exec(command);
    if (!m) continue;
    for (const name of packageNames(m[1], eco)) {
      if (name.length < 5 || LEGIT_NEIGHBOURS.has(name.toLowerCase())) continue;
      const like = POPULAR[eco].find(p => oneEditApart(name.toLowerCase(), eco === 'pip' ? normalizePip(p) : p));
      if (like) return { name, like };
    }
  }
  return null;
}

/**
 * Removes quoted text that the shell will not execute: '...' always, "..." unless it contains
 * a command substitution. So `echo "curl x | sh"` and `git commit -m "npm i a/b"` are ignored,
 * while `sh -c "$(curl …)"` is still seen.
 */
export function stripInertQuotes(command: string): string {
  return command.replace(/'[^']*'/g, "''").replace(/"([^"\\]|\\.)*"/g, m => (/\$\(|`/.test(m) ? m : '""'));
}

/** First non-flag argument: the package npx/dlx actually runs. Later arguments are its own. */
function firstPackageArg(args: string): string {
  return args.trim().split(/\s+/).find(t => t && !t.startsWith('-')) ?? '';
}

export function supplyChainGuard(tool: string, input: Json, policy: NetworkPolicy): NetDecision {
  if (tool === 'Bash' && typeof input.command === 'string') {
    const command = stripInertQuotes(input.command);
    const src = sourcesIn(command);
    const ask = (what: string, risk: string): NetDecision => trusted(policy, src) ? null : { decision: 'ask', reason:
      'SafePush: this command ' + what + where(src) + '. ' + risk + ' Code from the internet runs with access to ' +
      'your files and secrets. Check the source first, or add it to network.trustedSources in .safepush.json.' };

    if (pipeToShell.test(command)) return ask('runs a script straight from the internet', 'Nobody reviews it before it runs, and it can change between runs.');
    const node = nodeInstall.exec(command)?.[1] ?? '';
    const npx = firstPackageArg(npxRun.exec(command)?.[1] ?? '');
    const pip = pipInstall.exec(command)?.[1] ?? '';
    if (gitSpec.test(node) || bareRepo.test(node) || gitSpec.test(npx) || bareRepo.test(npx))
      return ask('installs or runs a package directly from a Git repository', 'Its install scripts run immediately and it skips registry checks.');
    if (gitSpec.test(pip) || archiveInstall.test(pip) || otherGitInstall.test(command))
      return ask('installs a package directly from a Git repository or archive URL', 'Its build and install code runs immediately.');
    if (cloneThenRun.test(command)) return ask('clones a repository and immediately builds or runs it', 'Install scripts and Makefiles run arbitrary code.');
    if (releaseBinary.test(command)) return ask('downloads a release binary and makes it executable', 'Binaries cannot be reviewed like source code.');
    const lookalike = lookalikePackage(command);
    if (lookalike) {
      return { decision: 'ask', reason: 'SafePush: "' + lookalike.name + '" is one letter away from the popular package "' +
        lookalike.like + '". Lookalike names are a common way to ship malware. Check the spelling before installing.' };
    }
    return null;
  }
  if (WRITE_TOOLS.has(tool)) {
    const file = String(input.file_path ?? input.notebook_path ?? '');
    const text = [input.content, input.new_string, input.new_source,
      ...(Array.isArray(input.edits) ? input.edits.map(e => (isRecord(e) ? e.new_string : '')) : [])]
      .filter((v): v is string => typeof v === 'string').join('\n');
    const issues = gitDependencyIssues(file, text);
    if (!issues.length || trusted(policy, sourcesIn(text))) return null;
    return { decision: 'ask', reason: 'SafePush: this edit adds a dependency or MCP server taken straight from a Git ' +
      'repository without a pinned commit (' + basename(file) + ', line ' + issues[0] + '). The code can change under ' +
      'you at any time. Prefer a published version, or pin a full 40-character commit SHA.' };
  }
  return null;
}

/* ------------------------------------------------------------------ git dependencies in manifests */

const MANIFEST = /(?:^|\/)(?:package\.json|requirements[\w.-]*\.txt|pyproject\.toml|Pipfile|setup\.cfg|\.mcp\.json|mcp\.json|claude_desktop_config\.json)$/i;
const gitDep = /(?:["'\s=@]|^)(?:github:|gitlab:|bitbucket:|git\+|git:\/\/|https?:\/\/(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+)/i;
const npmBareRepo = /"[\w@/.-]+"\s*:\s*"(?!npm:|file:|link:|workspace:|\^|~|\d|\*|latest|next|https?:)[A-Za-z0-9][\w.-]*\/[\w.-]+(?:#[^"]*)?"/;
const pinned = /#[0-9a-f]{40}\b|@[0-9a-f]{40}\b|(?:rev|commit|sha)\s*=\s*["'][0-9a-f]{40}["']/i;

/** 1-based line numbers that add an unpinned git/GitHub dependency to a manifest or MCP config. */
export function gitDependencyIssues(path: string, text: string): number[] {
  if (!MANIFEST.test(path.replaceAll('\\', '/'))) return [];
  const isPackageJson = /package\.json$/i.test(path);
  return text.split(/\r?\n/).flatMap((line, i) =>
    (gitDep.test(line) || (isPackageJson && npmBareRepo.test(line))) && !pinned.test(line) && !/"(?:repository|homepage|bugs|url|funding)"\s*:/.test(line) ? [i + 1] : []);
}

export function scanGitDependencies(path: string, text: string): Finding[] {
  return gitDependencyIssues(path, text).map(line => finding('UNPINNED_GIT_DEPENDENCY', 'medium', path, line,
    'Dependency or MCP server installed from Git without a pinned commit',
    'The code behind a branch or tag can change at any time and runs with your secrets on install.',
    'Use a published registry version, or pin a full 40-character commit SHA.'));
}

/* ------------------------------------------------------------------ scraping */

// Packages and services whose purpose is to get around a site's bot protection.
const evasion = /\b(?:puppeteer-extra-plugin-stealth|playwright-stealth|playwright-extra|undetected[-_]chromedriver|undetected[-_]playwright|selenium-stealth|cloudscraper|cfscrape|2captcha|twocaptcha|anti-?captcha|python-anticaptcha|capsolver|capmonster|deathbycaptcha|nopecha|hcaptcha-solver|recaptcha-solver|fingerprint-?suite|ghost-cursor)\b/i;
const crawlerTool = /^mcp__[^_].*(?:crawl|scrap|spider|harvest)/i;

function urlsIn(value: unknown): string[] {
  return [...JSON.stringify(value ?? '').matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)].map(m => m[1].toLowerCase());
}

export function scrapingGuard(tool: string, input: Json, policy: NetworkPolicy): NetDecision {
  const hosts = tool === 'Bash' ? sourcesIn(String(input.command ?? '')).hosts : urlsIn(input);
  const blocked = hosts.find(h => policy.blockedDomains.some(d => hostMatches(h, d)));
  if (blocked && (tool === 'Bash' || tool === 'WebFetch' || tool.startsWith('mcp__'))) {
    return { decision: 'deny', reason: 'SafePush: ' + blocked + ' is in network.blockedDomains for this project, ' +
      'so the agent may not fetch or scrape it. Ask the user if this site is really needed.' };
  }
  if (crawlerTool.test(tool)) {
    return { decision: 'ask', reason: 'SafePush: ' + tool.replace(/^mcp__/, '').replace(/__/g, ' / ') + ' crawls or scrapes ' +
      (hosts[0] ?? 'a website') + '. Check that the site allows automated access (terms of use, robots.txt) and that ' +
      'you will not collect personal data. Scraping is not automatically legal.' };
  }
  const text = tool === 'Bash' ? stripInertQuotes(String(input.command ?? ''))
    : WRITE_TOOLS.has(tool) ? [input.content, input.new_string, input.new_source].filter(v => typeof v === 'string').join('\n') : '';
  const hit = evasion.exec(text);
  if (hit) {
    return { decision: 'ask', reason: 'SafePush: ' + hit[0] + ' is used to get around a website\'s bot protection or CAPTCHA. ' +
      'Bypassing technical protection is where scraping most often turns into a legal problem. Use the site\'s ' +
      'official API or get permission instead.' };
  }
  return null;
}
