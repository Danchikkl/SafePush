/**
 * Encoded-secret detection.
 *
 * Agents (and prompt-injection payloads) often move secrets as base64, hex or URL-encoded
 * text, which defeats plain regexes. This module finds encoded-looking substrings, decodes
 * them up to MAX_DEPTH layers, and re-runs only the KNOWN credential patterns on the result.
 * Generic heuristics are not re-run on decoded text: that would explode false positives.
 */
import { finding, knownSecretProviders } from './rules.mjs';
import type { Finding } from './types.mjs';

const MAX_DEPTH = 3;
const MAX_CANDIDATES_PER_LINE = 20;
const base64Candidate = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
const hexCandidate = /\b(?:[0-9a-fA-F]{2}){16,}\b/g;
const percentCandidate = /(?:%[0-9A-Fa-f]{2}[^\s%]*){6,}/g;

function printable(text: string): boolean {
  if (!text) return false;
  let ok = 0;
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ok++;
  }
  return ok / text.length > 0.95;
}
function tryBase64(s: string): string | null {
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  if (normalized.replace(/=+$/, '').length % 4 === 1) return null;
  const out = Buffer.from(normalized, 'base64').toString('utf8');
  return printable(out) ? out : null;
}
function tryHex(s: string): string | null {
  const out = Buffer.from(s, 'hex').toString('utf8');
  return printable(out) ? out : null;
}
function tryPercent(s: string): string | null {
  try {
    const out = decodeURIComponent(s);
    return out !== s ? out : null;
  } catch { return null; }
}

/** Decoded layers found in text, breadth-first, never including the input itself. */
export function decodedLayers(text: string): string[] {
  const layers: string[] = [];
  let frontier = [text];
  for (let depth = 0; depth < MAX_DEPTH && frontier.length; depth++) {
    const next: string[] = [];
    for (const chunk of frontier) {
      const candidates = [
        ...[...chunk.matchAll(base64Candidate)].map(m => tryBase64(m[0])),
        ...[...chunk.matchAll(hexCandidate)].map(m => tryHex(m[0])),
        ...[...chunk.matchAll(percentCandidate)].map(m => tryPercent(m[0])),
      ].filter((v): v is string => v !== null).slice(0, MAX_CANDIDATES_PER_LINE);
      next.push(...candidates);
    }
    layers.push(...next);
    frontier = next;
  }
  return layers;
}

/** Providers of known credentials hidden under one or more encoding layers. */
export function encodedSecretProviders(text: string): string[] {
  if (knownSecretProviders(text).length) return []; // already visible; reported by the plain rule
  return [...new Set(decodedLayers(text).flatMap(knownSecretProviders))];
}

export function scanEncoded(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const providers = encodedSecretProviders(line);
    if (!providers.length) continue;
    findings.push(finding('ENCODED_SECRET', 'high', path, index + 1,
      'Possible encoded ' + providers[0],
      'A known credential format appears after decoding base64, hex or URL encoding. Encoding is not protection.',
      'If real, revoke/rotate it and load it from a server-side secret store instead.'));
  }
  return findings;
}
