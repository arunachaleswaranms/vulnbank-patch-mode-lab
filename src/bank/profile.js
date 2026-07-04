/**
 * VulnBank workshop run-profile + Patch Mode gating.
 *
 * ── Legacy env model (unchanged) ──────────────────────────────────────
 * BANK_PROFILE=participant (default) forces every HARDEN_Ln toggle off,
 * regardless of what's actually set in the environment -- the safety net
 * that stops a stray env var from handing participants a hardened (boring)
 * agent. BANK_PROFILE=demo is the presenter's profile; only there do
 * HARDEN_L1..HARDEN_L5 and AIM_ENFORCEMENT actually control anything.
 *
 * ── Patch Mode (new) ──────────────────────────────────────────────────
 * The dashboard "Patch Mode" toggle drives an in-memory override layer on
 * top of the legacy model, so hardening can be switched live (no restart,
 * no demo profile required -- turning hardening *on* is always the safe
 * direction). isHardenEnabled() is the single source of truth every
 * security control checks:
 *
 *   1. an explicit per-level override (set via the dashboard), else
 *   2. an explicit global override (set via the dashboard / PATCH_MODE), else
 *   3. the legacy BANK_PROFILE + HARDEN_Ln env behavior.
 *
 * Default is OFF (PATCH_MODE=off, no overrides) -> legacy path -> vulnerable
 * lab preserved byte-for-byte.
 */

const LEVELS = [1, 2, 3, 4, 5];

// null = "not set, fall through to the next layer". true/false = explicit.
const overrides = { global: null };
for (const l of LEVELS) overrides[l] = null;

// Seed the global override from the PATCH_MODE env var at boot. Only
// PATCH_MODE=on seeds an override; the default (off / unset) leaves the
// legacy BANK_PROFILE + HARDEN_L* env behavior fully intact.
if (String(process.env.PATCH_MODE || 'off').toLowerCase() === 'on') {
  overrides.global = true;
}

export function getBankProfile() {
  return process.env.BANK_PROFILE === 'demo' ? 'demo' : 'participant';
}

function legacyHarden(level) {
  if (getBankProfile() !== 'demo') return false;
  return process.env[`HARDEN_L${level}`] === 'on';
}

/**
 * The single gate every Patch Mode security control consults.
 */
export function isHardenEnabled(level) {
  const per = overrides[level];
  if (per === true || per === false) return per;
  if (overrides.global === true || overrides.global === false) return overrides.global;
  return legacyHarden(level);
}

/**
 * L5 additionally respects DVAA's existing AIM_ENFORCEMENT variable. Both
 * must agree for L5's AIM gate to be live: L5 hardening on AND
 * AIM_ENFORCEMENT is not explicitly 'off'.
 */
export function isL5AimEnforced() {
  return isHardenEnabled(5) && process.env.AIM_ENFORCEMENT !== 'off';
}

// ── Dashboard Patch Mode controls ─────────────────────────────────────

function norm(state) {
  if (state === true || state === 'on') return true;
  if (state === false || state === 'off') return false;
  return null; // 'auto' / null clears the override
}

/** Set the global Patch Mode override; clears per-level overrides so the
 *  global setting governs uniformly until a level is individually toggled. */
export function setPatchGlobal(state) {
  overrides.global = norm(state);
  for (const l of LEVELS) overrides[l] = null;
  return getPatchState();
}

/** Set (or clear) a single level's override. level: 1..5. */
export function setPatchLevel(level, state) {
  const n = Number(level);
  if (!LEVELS.includes(n)) throw new Error(`invalid level: ${level}`);
  overrides[n] = norm(state);
  return getPatchState();
}

/** True if any level is currently hardened (used for the global UI badge). */
export function isPatchModeOn() {
  return LEVELS.some((l) => isHardenEnabled(l));
}

export function getPatchState() {
  const levels = {};
  const effective = {};
  for (const l of LEVELS) {
    levels[l] = overrides[l]; // explicit per-level override (or null)
    effective[l] = isHardenEnabled(l); // what's actually in force
  }
  return {
    global: overrides.global,
    anyOn: isPatchModeOn(),
    allOn: LEVELS.every((l) => isHardenEnabled(l)),
    levels,
    effective,
    profile: getBankProfile(),
  };
}
