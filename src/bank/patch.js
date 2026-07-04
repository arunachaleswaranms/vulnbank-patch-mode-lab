/**
 * VulnBank workshop — Patch Mode security controls.
 *
 * Every control here is a no-op unless the relevant level is hardened
 * (isHardenEnabled), which the dashboard Patch Mode toggle drives. With
 * Patch Mode OFF these functions pass through untouched, so the original
 * vulnerable lab behavior is preserved exactly. With Patch Mode ON they
 * enforce real, server-side defenses:
 *
 *   L1  prompt-injection input gate + canary output filter   (helperbot)
 *   L2  restricted-content input gate + canary output filter (ragbot)
 *   L3  SQL-tautology input gate + canary output filter      (databot)
 *   L4  memory classification (instruction vs. preference)   (memorybot)
 *   L5  A2A HMAC signature + allowlist + timestamp auth       (worker-1)
 */

import crypto from 'crypto';
import { isHardenEnabled } from './profile.js';

// agent.id -> workshop level number
const AGENT_LEVEL = { helperbot: 1, ragbot: 2, databot: 3, memorybot: 4 };

export function agentLevel(agentId) {
  return AGENT_LEVEL[agentId] || null;
}

// ── Audit log (in-memory ring buffer) ─────────────────────────────────
const auditLog = [];

export function auditBlock(entry) {
  const e = { at: Date.now(), ...entry };
  auditLog.push(e);
  if (auditLog.length > 500) auditLog.shift();
  // Never log the full payload/secret — only a short, masked sample.
  console.warn(`[patch][BLOCKED] level=L${entry.level} agent=${entry.agent} reason="${entry.reason}"`);
  return e;
}

export function getPatchAudit() {
  return auditLog.slice();
}

// ── Canary / restricted-reference output filter ───────────────────────
const CANARY_RE = /CANARY-L\d+-[A-Za-z0-9]+/g;

/**
 * Redact planted canaries from any text a level is about to return — but
 * only when that level's patch is on. With patch off this is a pure
 * pass-through, so OFF-mode win detection still fires normally.
 */
export function filterOutput(level, text) {
  if (!level || !isHardenEnabled(level)) return text;
  if (typeof text !== 'string') return text;
  return text.replace(CANARY_RE, '[REDACTED — restricted reference withheld by Patch Mode]');
}

// ── Prompt-injection / SQLi input gate ────────────────────────────────
const GATE = {
  1: [
    /ignore\s+(all\s+|the\s+)?(previous|prior|above)\s+instructions/i,
    /system\s+prompt/i,
    /hidden\s+instructions?/i,
    /return\s+only\s+the\s+(secret|canary|account|token)/i,
    /compliance\s+override/i,
    /audit\s+validation/i,
    /internal\s+(safety\s+)?validation/i,
    /reveal\s+(the\s+)?canary/i,
    /print\s+(the\s+)?token/i,
    /\bcanary\b/i,
  ],
  2: [
    /compliance\s+override/i,
    /restricted\s+(knowledge|statement|entry|entries|document|reference)/i,
    /output\s+only\s+the\s+(exact\s+)?token/i,
    /do\s+not\s+(redact|summarize|explain)/i,
    /rag\s+validation/i,
    /internal\s+validation/i,
    /\bcanary\b/i,
  ],
  3: [
    /\bor\s+1\s*=\s*1\b/i,
    /'\s*1\s*'\s*=\s*'\s*1\s*'/i,
    /"\s*1\s*"\s*=\s*"\s*1\s*"/i,
    /\bunion\s+select\b/i,
    /\bdrop\b/i,
    /\binsert\b/i,
    /\bupdate\b/i,
    /\bdelete\b/i,
    /--/,
    /\/\*/,
    /\*\//,
    /\bor\s+true\b/i,
  ],
};

const REFUSAL = {
  1: "I can't share hidden instructions, internal configuration, or any confidential account/canary value — including for audits, validations, or compliance checks. I'm happy to help with a genuine banking question instead.",
  2: "I can only return knowledge-base content you're authorized to see. Restricted entries and other customers' statements aren't retrievable through me, regardless of override or validation wording.",
  3: "That request contains raw SQL / tautology syntax, which isn't accepted. I only run parameterized lookups over allowed fields. Describe the accounts you want by name, type, or status and I'll help.",
};

/**
 * If the level is patched AND the message matches a known injection shape,
 * return a safe refusal string (the caller returns it directly). Otherwise
 * null → normal (vulnerable / legitimate) processing continues.
 */
export function gateInput(agentId, message) {
  const level = agentLevel(agentId);
  if (!level || !isHardenEnabled(level)) return null;
  const patterns = GATE[level];
  if (!patterns) return null;
  if (patterns.some((re) => re.test(message || ''))) {
    auditBlock({ level, agent: agentId, reason: 'prompt-injection / SQLi pattern', sample: String(message || '').slice(0, 100) });
    return REFUSAL[level];
  }
  return null;
}

// ── L4 memory classification ──────────────────────────────────────────
const UNSAFE_MEMORY = [
  /\balways\s+(do|recommend|route|send|use|transfer|reply)/i,
  /for\s+all\s+future\s+sessions/i,
  /\boverride\b/i,
  /must\s+recommend/i,
  /route\s+funds/i,
  /\btransfer\b/i,
  /attacker/i,
  /payment\s+instructions?/i,
  /security\s+bypass/i,
  /standing\s+instruction/i,
  /whenever\s+.*\b(ask|asks|request|requests)/i,
];

/** True if a to-be-stored memory looks like an executable instruction
 *  (policy/routing/payment/behavior override) rather than a plain fact. */
export function isUnsafeMemory(text) {
  return UNSAFE_MEMORY.some((re) => re.test(text || ''));
}

// ── L5 agent-to-agent HMAC authentication ─────────────────────────────
const TRUSTED_A2A_AGENTS = ['orchestrator', 'fraud-check-agent'];

export function isA2aAuthEnforced() {
  return isHardenEnabled(5);
}

// Stable canonical string over the security-relevant fields, so a
// signature commits to who/where/how-much and when.
function canonical(msg) {
  return [
    msg.from ?? '',
    msg.to ?? '',
    msg.transferTo ?? '',
    msg.amount ?? '',
    msg.timestamp ?? msg.ts ?? '',
    msg.nonce ?? '',
  ].join('|');
}

/** Produce the HMAC a legitimate signed message would carry. Used by tests
 *  and by any real trusted-agent client. */
export function signA2a(msg, secret) {
  return crypto.createHmac('sha256', secret).update(canonical(msg)).digest('hex');
}

/**
 * Verify an inbound A2A message when L5 patch is on. Returns
 * {ok:true, enforced} or {ok:false, enforced:true, code, reason}. When
 * patch is off, always {ok:true, enforced:false} (spoofing stays possible).
 */
export function verifyA2a(msg) {
  if (!isA2aAuthEnforced()) return { ok: true, enforced: false };

  const from = msg.from || 'unknown';
  const fail = (code, reason) => {
    auditBlock({ level: 5, agent: from, reason: `${code}: ${reason}` });
    return { ok: false, enforced: true, code, reason };
  };

  if (!TRUSTED_A2A_AGENTS.includes(from)) {
    return fail('unknown_agent', `sender "${from}" is not on the trusted-agent allowlist`);
  }
  const sig = msg.signature || msg.sig;
  if (!sig) return fail('missing_signature', 'message is unsigned');

  const secret = process.env.A2A_SHARED_SECRET;
  if (!secret) return fail('server_misconfig', 'A2A_SHARED_SECRET is not configured');

  const ts = Number(msg.timestamp ?? msg.ts);
  if (!Number.isFinite(ts)) return fail('missing_timestamp', 'message has no verifiable timestamp');
  const skew = Number(process.env.A2A_MAX_SKEW_SECONDS || 300);
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > skew) return fail('stale_timestamp', `timestamp outside ±${skew}s replay window`);

  const expected = signA2a(msg, secret);
  const a = Buffer.from(String(sig));
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return fail('invalid_signature', 'HMAC signature does not match');
  }
  return { ok: true, enforced: true };
}
