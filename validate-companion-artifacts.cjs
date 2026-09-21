#!/usr/bin/env node

/**
 * Validates the companion artifacts this edition adds on top of the Cloudflare
 * workflow, and their cross-references into findings.json and
 * coverage-ledger.json.
 *
 * Usage: node validate-companion-artifacts.cjs <output-dir>
 *
 * Artifacts checked when present:
 *   history-leads.json
 *   reflection-log.json
 *   reproduction-ladder.json
 *   calibration-log.json
 *   chains.json
 *
 * findings.json is required; coverage-ledger.json is required only when an
 * artifact references a coverage unit. An absent optional artifact is reported,
 * never failed: a run that produced some of them still validates what it did
 * produce.
 *
 * Dependency-free. Reads with the same no-follow, nonblocking, size-bounded
 * discipline as the two original validators.
 */

const fs = require("fs");
const path = require("path");
const { TextDecoder } = require("util");

const LIMITS = Object.freeze({
  inputBytes: 5 * 1024 * 1024,
  arrayItems: 10000,
  stringBytes: 65536,
  validationErrors: 100,
});

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const VISIBLE_CONTENT = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const FINGERPRINT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;
const CHAIN_ID_PATTERN = /^chain-[0-9a-f]{8,64}$/;
const LEAD_ID_PATTERN = /^hl-[0-9a-zA-Z_-]{1,32}$/;
const INSIGHT_ID_PATTERN = /^rl-[0-9a-zA-Z_-]{1,32}$/;
const GIT_REV_PATTERN = /^[0-9a-f]{40}$/;
const REPO_PATH_FORBIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;

const SEVERITY_RANK = new Map([
  ["informational", 0],
  ["low", 1],
  ["medium", 2],
  ["high", 3],
  ["critical", 4],
]);

const RUNG_RANK = new Map([
  ["R0", 0],
  ["R0.5", 1],
  ["R1", 2],
  ["R2", 3],
  ["R3", 4],
  ["R3a", 5],
]);
const CONFIRMABLE_RUNGS = new Set(["R3", "R3a"]);

const HISTORY_SIGNALS = new Set([
  "revert_of_security_fix",
  "guard_removed",
  "guard_weakened",
  "parallel_path_unpatched",
  "fix_pattern_generalized",
  "secret_in_history",
]);
const HISTORY_STATUSES = new Set(["full", "partial_shallow", "unsupported_vcs"]);
const PRESENT_STATUSES = new Set(["live", "resolved_by_source", "unverifiable"]);
const ANCHOR_STATUSES = new Set(["enforcement_absent", "enforcement_moved", "still_enforced", "parallel_path"]);
const LEAD_DISPOSITIONS = new Set(["open", "assigned", "superseded_by_finding", "dropped"]);
const CONFIDENCE_SOURCES = new Set(["source_read", "blame_only"]);

const INSIGHT_CLASSES = new Set([
  "false_assumption",
  "blocked_method",
  "boundary_fact",
  "rejection_reason",
  "unit_shape",
  "missing_result",
]);
const INSIGHT_SOURCES = new Set(["hunter_result", "verifier_result", "parent_validation", "promotion"]);
const INSIGHT_DIRECTIVES = new Set(["avoid", "prefer", "note"]);
const INSIGHT_SCOPES = new Set(["unit", "subsystem", "run"]);
const INSIGHT_STATUSES = new Set(["active", "superseded"]);

const ENVIRONMENT_TIERS = new Set(["static", "microvm", "hardened_container"]);
const EVIDENCE_CHANNELS = new Set(["a", "b"]);

const ATTACKER_POSITIONS = new Set([
  "external",
  "internal_network",
  "in_cluster",
  "local",
  "host_system",
  "supply_chain",
  "physical",
]);

const FORCE_LOW_RULES = new Set([
  "unreachable_inputs",
  "dependency_unreached",
  "vague_call_path",
  "unreliable_trigger",
  "prerequisite_equal_privilege",
  "physical_sustained",
  "trusted_controller_zero_delta",
  "host_to_guest_standard",
]);
const CAP_HIGH_RULES = new Set([
  "exposure_internal",
  "reflected_or_self_xss",
  "probabilistic_trigger",
  "supply_chain_prerequisite",
  "non_default_configuration",
  "trusted_controller_critical_bypass",
  "confidential_computing_host",
]);
const CAP_MEDIUM_RULES = new Set([
  "local_vector",
  "self_contained_blast",
  "rarely_exposed",
  "equivalent_primitive",
  "documented_insecure",
  "physical_brief",
  "privileged_external",
  "trusted_controller_standard_bypass",
  "rare_parameter",
]);
const ESCALATION_RULES = new Set(["security_control_bypass"]);
const CALIBRATION_RULES = new Set([
  ...FORCE_LOW_RULES,
  ...CAP_HIGH_RULES,
  ...CAP_MEDIUM_RULES,
  ...ESCALATION_RULES,
]);
const CAP_CEILING = new Map([
  ...[...FORCE_LOW_RULES].map((rule) => [rule, "low"]),
  ...[...CAP_MEDIUM_RULES].map((rule) => [rule, "medium"]),
  ...[...CAP_HIGH_RULES].map((rule) => [rule, "high"]),
]);
const CHECKLIST_OUTCOMES = new Set(["applies", "does_not_apply", "unknown"]);

const CHAIN_VERDICTS = new Set(["confirmed", "open", "refuted"]);
const LINK_STATUSES = new Set(["supported", "open", "refuted"]);
const LINK_ROLES = new Set(["entry", "pivot", "terminal"]);
const CORRELATION_KINDS = new Set(["shared_symbol", "shared_file", "shared_attack_class"]);
const USER_INTERACTION = new Set(["required", "none"]);

class SafeInputError extends Error {}

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

function escapeUnsafeDiagnosticCharacters(text) {
  return String(text).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const code = character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    return `\\u{${code}}`;
  });
}

function safeQuote(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const trimmed = String(text).slice(0, 200);
  return `"${escapeUnsafeDiagnosticCharacters(trimmed)}"`;
}

function isVisibleText(value, maxBytes = LIMITS.stringBytes) {
  if (typeof value !== "string") return false;
  if (Buffer.byteLength(value, "utf8") > maxBytes) return false;
  return VISIBLE_CONTENT.test(value);
}

function isSafeRepoPath(value) {
  if (!isVisibleText(value, 4096)) return false;
  if (REPO_PATH_FORBIDDEN.test(value)) return false;
  if (value.startsWith("/") || value.startsWith("~") || /^[A-Za-z]:/.test(value)) return false;
  if (value.startsWith("\\")) return false;
  const segments = value.split(/[\\/]/);
  return !segments.some((segment) => segment === "." || segment === "..");
}

/**
 * Opens with O_NOFOLLOW and O_NONBLOCK, the same protection the two original
 * validators require. Node on native Windows does not expose these constants;
 * that is a deliberate refusal to read rather than a bug to work around.
 */
function readFileWithinLimit(file) {
  const noFollow = fs.constants.O_NOFOLLOW;
  const nonBlock = fs.constants.O_NONBLOCK;
  if (!Number.isInteger(noFollow) || noFollow === 0 || !Number.isInteger(nonBlock) || nonBlock === 0) {
    throw new SafeInputError("OS no-follow and nonblocking input protection is unavailable");
  }

  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlock);
  } catch (error) {
    if (error && (error.code === "ELOOP" || error.code === "EMLINK")) {
      throw new SafeInputError("input must not be a symlink");
    }
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new SafeInputError("input must be a regular file");
    if (stat.size > LIMITS.inputBytes) {
      throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
    }
    const chunks = [];
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytesRead = 0;
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      bytesRead += count;
      if (bytesRead > LIMITS.inputBytes) {
        throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
      }
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    try {
      return UTF8_DECODER.decode(Buffer.concat(chunks, bytesRead));
    } catch {
      throw new SafeInputError("input must be valid UTF-8");
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function loadJson(file) {
  const contents = readFileWithinLimit(file);
  try {
    return JSON.parse(contents);
  } catch {
    throw new SafeInputError("invalid JSON syntax");
  }
}

// ---------------------------------------------------------------------------
// Shared reference context
// ---------------------------------------------------------------------------

function buildContext(findings, ledger) {
  const fingerprints = new Map();
  const confirmed = new Set();
  if (Array.isArray(findings)) {
    for (const record of findings) {
      if (!isObject(record) || typeof record.fingerprint !== "string") continue;
      fingerprints.set(record.fingerprint, record);
      if (record.verdict === "confirmed") confirmed.add(record.fingerprint);
    }
  }
  const coverageIds = new Set();
  if (Array.isArray(ledger)) {
    for (const unit of ledger) {
      if (isObject(unit) && typeof unit.coverage_id === "string") coverageIds.add(unit.coverage_id);
    }
  }
  return { fingerprints, confirmed, coverageIds, ledgerLoaded: Array.isArray(ledger) };
}

function checkFingerprintRef(errors, context, base, value, { mustBeConfirmed = false } = {}) {
  if (typeof value !== "string" || !FINGERPRINT_PATTERN.test(value)) {
    errors.push(`${base}: invalid fingerprint ${safeQuote(value)}`);
    return false;
  }
  if (!context.fingerprints.has(value)) {
    errors.push(`${base}: fingerprint ${safeQuote(value)} is not in findings.json`);
    return false;
  }
  if (mustBeConfirmed && !context.confirmed.has(value)) {
    const verdict = context.fingerprints.get(value).verdict;
    errors.push(`${base}: fingerprint ${safeQuote(value)} has verdict ${safeQuote(verdict)}, expected confirmed`);
    return false;
  }
  return true;
}

function checkCoverageRefs(errors, context, base, values) {
  if (!Array.isArray(values) || values.length === 0) {
    errors.push(`${base}: must be a non-empty array of coverage IDs`);
    return;
  }
  values.forEach((value, index) => {
    if (!isVisibleText(value)) {
      errors.push(`${base}[${index}]: invalid coverage ID`);
      return;
    }
    if (context.ledgerLoaded && !context.coverageIds.has(value)) {
      errors.push(`${base}[${index}]: coverage ID ${safeQuote(value)} is not in coverage-ledger.json`);
    }
  });
  if (!context.ledgerLoaded) {
    errors.push(`${base}: coverage-ledger.json is required to check these references but was not loaded`);
  }
}

function requireKeys(errors, base, object, keys) {
  let ok = true;
  for (const key of keys) {
    if (!hasOwn(object, key)) {
      errors.push(`${base}.${key}: required`);
      ok = false;
    }
  }
  return ok;
}

function rejectUnknownKeys(errors, base, object, allowed) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) errors.push(`${base}.${escapeUnsafeDiagnosticCharacters(key)}: unknown property`);
  }
}

function expectArray(errors, value, label) {
  if (!Array.isArray(value)) {
    errors.push(`${label}: must be a JSON array`);
    return false;
  }
  if (value.length > LIMITS.arrayItems) {
    errors.push(`${label}: exceeds ${LIMITS.arrayItems} entries`);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// history-leads.json
// ---------------------------------------------------------------------------

const HISTORY_KEYS = new Set([
  "lead_id",
  "coverage_ids",
  "signal",
  "fix_rev",
  "regression_rev",
  "rev_date",
  "rev_subject",
  "historical_paths",
  "invariant",
  "present_anchor",
  "present_status",
  "hypothesis",
  "confidence_source",
  "history_status",
  "linked_fingerprints",
  "disposition",
  "disposition_reason",
]);

function validateHistoryLeads(leads, context) {
  const errors = [];
  if (!expectArray(errors, leads, "history-leads.json")) return errors;
  const seen = new Set();

  leads.forEach((lead, index) => {
    const base = `$[${index}]`;
    if (!isObject(lead)) {
      errors.push(`${base}: must be an object`);
      return;
    }
    requireKeys(errors, base, lead, [
      "lead_id",
      "coverage_ids",
      "signal",
      "fix_rev",
      "invariant",
      "present_status",
      "hypothesis",
      "history_status",
      "disposition",
    ]);
    rejectUnknownKeys(errors, base, lead, HISTORY_KEYS);

    if (typeof lead.lead_id !== "string" || !LEAD_ID_PATTERN.test(lead.lead_id)) {
      errors.push(`${base}.lead_id: expected hl-<id>, got ${safeQuote(lead.lead_id)}`);
    } else if (seen.has(lead.lead_id)) {
      errors.push(`${base}.lead_id: duplicate ${safeQuote(lead.lead_id)}`);
    } else {
      seen.add(lead.lead_id);
    }

    if (!HISTORY_SIGNALS.has(lead.signal)) errors.push(`${base}.signal: invalid ${safeQuote(lead.signal)}`);
    if (!HISTORY_STATUSES.has(lead.history_status)) {
      errors.push(`${base}.history_status: invalid ${safeQuote(lead.history_status)}`);
    }
    if (!PRESENT_STATUSES.has(lead.present_status)) {
      errors.push(`${base}.present_status: invalid ${safeQuote(lead.present_status)}`);
    }
    if (!LEAD_DISPOSITIONS.has(lead.disposition)) {
      errors.push(`${base}.disposition: invalid ${safeQuote(lead.disposition)}`);
    }
    if (hasOwn(lead, "confidence_source") && !CONFIDENCE_SOURCES.has(lead.confidence_source)) {
      errors.push(`${base}.confidence_source: invalid ${safeQuote(lead.confidence_source)}`);
    }
    if (typeof lead.fix_rev !== "string" || !GIT_REV_PATTERN.test(lead.fix_rev)) {
      errors.push(`${base}.fix_rev: expected a 40-character lowercase hex commit`);
    }
    if (hasOwn(lead, "regression_rev") && lead.regression_rev !== null) {
      if (typeof lead.regression_rev !== "string" || !GIT_REV_PATTERN.test(lead.regression_rev)) {
        errors.push(`${base}.regression_rev: expected a 40-character lowercase hex commit or null`);
      }
    }
    if (!isVisibleText(lead.invariant)) errors.push(`${base}.invariant: must be non-empty text`);
    if (!isVisibleText(lead.hypothesis)) errors.push(`${base}.hypothesis: must be non-empty text`);

    // Only a live lead must be linked to a unit. A lead resolved by current
    // source, or one with no boundary unit to attach to, records an empty array.
    if (!Array.isArray(lead.coverage_ids)) {
      errors.push(`${base}.coverage_ids: must be an array`);
    } else if (lead.present_status === "live") {
      checkCoverageRefs(errors, context, `${base}.coverage_ids`, lead.coverage_ids);
    } else if (lead.coverage_ids.length > 0) {
      checkCoverageRefs(errors, context, `${base}.coverage_ids`, lead.coverage_ids);
    }

    if (hasOwn(lead, "historical_paths")) {
      if (!Array.isArray(lead.historical_paths) || lead.historical_paths.length === 0) {
        errors.push(`${base}.historical_paths: must be a non-empty array`);
      } else {
        lead.historical_paths.forEach((entry, i) => {
          const withoutLine = typeof entry === "string" ? entry.replace(/:\d+$/, "") : entry;
          if (!isSafeRepoPath(withoutLine)) {
            errors.push(`${base}.historical_paths[${i}]: expected a repository-relative path`);
          }
        });
      }
    }

    if (hasOwn(lead, "present_anchor") && lead.present_anchor !== null) {
      const anchor = lead.present_anchor;
      const anchorBase = `${base}.present_anchor`;
      if (!isObject(anchor)) {
        errors.push(`${anchorBase}: must be an object or null`);
      } else {
        rejectUnknownKeys(errors, anchorBase, anchor, new Set(["path", "symbol", "status"]));
        if (!isSafeRepoPath(anchor.path)) errors.push(`${anchorBase}.path: expected a repository-relative path`);
        if (!ANCHOR_STATUSES.has(anchor.status)) {
          errors.push(`${anchorBase}.status: invalid ${safeQuote(anchor.status)}`);
        }
      }
    }

    if (hasOwn(lead, "linked_fingerprints")) {
      if (!Array.isArray(lead.linked_fingerprints)) {
        errors.push(`${base}.linked_fingerprints: must be an array`);
      } else {
        lead.linked_fingerprints.forEach((fp, i) => {
          checkFingerprintRef(errors, context, `${base}.linked_fingerprints[${i}]`, fp);
        });
      }
    }

    // A lead is never evidence: it may not carry a severity or a verdict.
    for (const forbidden of ["severity", "verdict", "impact", "secret", "credential", "value"]) {
      if (hasOwn(lead, forbidden)) {
        errors.push(`${base}.${forbidden}: a history lead must not carry ${forbidden}`);
      }
    }

    if (lead.signal === "secret_in_history" && lead.present_status === "live" && lead.disposition === "open") {
      // Permitted, but the lead must not be the only record of it.
      if (!Array.isArray(lead.linked_fingerprints)) {
        errors.push(`${base}.linked_fingerprints: a live secret_in_history lead must declare the array, even empty`);
      }
    }
  });

  return errors;
}

// ---------------------------------------------------------------------------
// reflection-log.json
// ---------------------------------------------------------------------------

const INSIGHT_KEYS = new Set([
  "insight_id",
  "wave",
  "class",
  "target",
  "insight",
  "evidence_paths",
  "source",
  "directive",
  "scope",
  "status",
  "superseded_by",
]);

function validateReflectionLog(entries, context) {
  const errors = [];
  if (!expectArray(errors, entries, "reflection-log.json")) return errors;
  const seen = new Set();
  const ids = new Set();

  for (const entry of entries) {
    if (isObject(entry) && typeof entry.insight_id === "string") ids.add(entry.insight_id);
  }

  entries.forEach((entry, index) => {
    const base = `$[${index}]`;
    if (!isObject(entry)) {
      errors.push(`${base}: must be an object`);
      return;
    }
    requireKeys(errors, base, entry, ["insight_id", "wave", "class", "target", "insight", "source", "scope", "status"]);
    rejectUnknownKeys(errors, base, entry, INSIGHT_KEYS);

    if (typeof entry.insight_id !== "string" || !INSIGHT_ID_PATTERN.test(entry.insight_id)) {
      errors.push(`${base}.insight_id: expected rl-<id>, got ${safeQuote(entry.insight_id)}`);
    } else if (ids.has(entry.insight_id) && seen.has(entry.insight_id)) {
      errors.push(`${base}.insight_id: duplicate ${safeQuote(entry.insight_id)}`);
    } else {
      seen.add(entry.insight_id);
    }

    if (!Number.isInteger(entry.wave) || entry.wave < 1) errors.push(`${base}.wave: expected a positive integer`);
    if (!INSIGHT_CLASSES.has(entry.class)) errors.push(`${base}.class: invalid ${safeQuote(entry.class)}`);
    if (!INSIGHT_SOURCES.has(entry.source)) errors.push(`${base}.source: invalid ${safeQuote(entry.source)}`);
    if (!INSIGHT_SCOPES.has(entry.scope)) errors.push(`${base}.scope: invalid ${safeQuote(entry.scope)}`);
    if (!INSIGHT_STATUSES.has(entry.status)) errors.push(`${base}.status: invalid ${safeQuote(entry.status)}`);
    if (hasOwn(entry, "directive") && !INSIGHT_DIRECTIVES.has(entry.directive)) {
      errors.push(`${base}.directive: invalid ${safeQuote(entry.directive)}`);
    }
    if (!isVisibleText(entry.insight)) errors.push(`${base}.insight: must be non-empty text`);

    if (entry.status === "superseded") {
      if (typeof entry.superseded_by !== "string" || !INSIGHT_ID_PATTERN.test(entry.superseded_by)) {
        errors.push(`${base}.superseded_by: a superseded insight must name the insight that replaced it`);
      } else if (!ids.has(entry.superseded_by)) {
        errors.push(`${base}.superseded_by: ${safeQuote(entry.superseded_by)} is not in this log`);
      } else if (entry.superseded_by === entry.insight_id) {
        errors.push(`${base}.superseded_by: an insight cannot supersede itself`);
      }
    } else if (hasOwn(entry, "superseded_by") && entry.superseded_by !== null) {
      errors.push(`${base}.superseded_by: must be null unless status is superseded`);
    }

    const target = entry.target;
    const targetBase = `${base}.target`;
    if (!isObject(target)) {
      errors.push(`${targetBase}: must be an object`);
    } else {
      rejectUnknownKeys(errors, targetBase, target, new Set(["coverage_ids", "paths", "fingerprints"]));
      const hasCoverage = Array.isArray(target.coverage_ids) && target.coverage_ids.length > 0;
      const hasPaths = Array.isArray(target.paths) && target.paths.length > 0;
      const hasFingerprints = Array.isArray(target.fingerprints) && target.fingerprints.length > 0;
      if (!hasCoverage && !hasPaths && !hasFingerprints) {
        errors.push(`${targetBase}: must name at least one coverage ID, path, or fingerprint`);
      }
      if (hasCoverage) checkCoverageRefs(errors, context, `${targetBase}.coverage_ids`, target.coverage_ids);
      if (hasPaths) {
        target.paths.forEach((value, i) => {
          if (!isSafeRepoPath(value)) errors.push(`${targetBase}.paths[${i}]: expected a repository-relative path`);
        });
      }
      if (hasFingerprints) {
        target.fingerprints.forEach((fp, i) => {
          checkFingerprintRef(errors, context, `${targetBase}.fingerprints[${i}]`, fp);
        });
      }
    }

    for (const forbidden of ["severity", "verdict", "payload", "exploit"]) {
      if (hasOwn(entry, forbidden)) {
        errors.push(`${base}.${forbidden}: a reflection insight must not carry ${forbidden}`);
      }
    }
  });

  return errors;
}

// ---------------------------------------------------------------------------
// reproduction-ladder.json
// ---------------------------------------------------------------------------

const LADDER_KEYS = new Set([
  "fingerprint",
  "rung_reached",
  "rung_attempted",
  "evidence_channel",
  "environment_tier",
  "capability_blocker",
]);

function validateReproductionLadder(entries, context) {
  const errors = [];
  if (!expectArray(errors, entries, "reproduction-ladder.json")) return errors;
  const seen = new Set();

  entries.forEach((entry, index) => {
    const base = `$[${index}]`;
    if (!isObject(entry)) {
      errors.push(`${base}: must be an object`);
      return;
    }
    requireKeys(errors, base, entry, ["fingerprint", "rung_reached", "rung_attempted", "environment_tier"]);
    rejectUnknownKeys(errors, base, entry, LADDER_KEYS);

    const fingerprintOk = checkFingerprintRef(errors, context, `${base}.fingerprint`, entry.fingerprint);
    if (fingerprintOk) {
      if (seen.has(entry.fingerprint)) {
        errors.push(`${base}.fingerprint: duplicate entry for ${safeQuote(entry.fingerprint)}`);
      } else {
        seen.add(entry.fingerprint);
      }
    }

    const reachedRank = RUNG_RANK.get(entry.rung_reached);
    const attemptedRank = RUNG_RANK.get(entry.rung_attempted);
    if (reachedRank === undefined) errors.push(`${base}.rung_reached: invalid ${safeQuote(entry.rung_reached)}`);
    if (attemptedRank === undefined) errors.push(`${base}.rung_attempted: invalid ${safeQuote(entry.rung_attempted)}`);
    if (reachedRank !== undefined && attemptedRank !== undefined && reachedRank > attemptedRank) {
      errors.push(`${base}.rung_reached: cannot exceed rung_attempted`);
    }

    if (!ENVIRONMENT_TIERS.has(entry.environment_tier)) {
      errors.push(`${base}.environment_tier: invalid ${safeQuote(entry.environment_tier)}`);
    }
    if (entry.environment_tier === "static" && reachedRank !== undefined && reachedRank > RUNG_RANK.get("R0.5")) {
      errors.push(`${base}.rung_reached: ${safeQuote(entry.rung_reached)} is unreachable on the static tier`);
    }

    if (hasOwn(entry, "evidence_channel") && entry.evidence_channel !== null) {
      if (!EVIDENCE_CHANNELS.has(entry.evidence_channel)) {
        errors.push(`${base}.evidence_channel: invalid ${safeQuote(entry.evidence_channel)}`);
      }
    }
    if (reachedRank !== undefined && reachedRank >= RUNG_RANK.get("R1")) {
      if (!hasOwn(entry, "evidence_channel") || !EVIDENCE_CHANNELS.has(entry.evidence_channel)) {
        errors.push(`${base}.evidence_channel: a rung at or above R1 requires a reached-sink evidence channel`);
      }
    }

    if (
      reachedRank !== undefined &&
      attemptedRank !== undefined &&
      reachedRank < attemptedRank &&
      !isVisibleText(entry.capability_blocker)
    ) {
      errors.push(`${base}.capability_blocker: required when the attempted rung was not reached`);
    }

    if (fingerprintOk && context.confirmed.has(entry.fingerprint) && !CONFIRMABLE_RUNGS.has(entry.rung_reached)) {
      errors.push(
        `${base}.rung_reached: ${safeQuote(entry.fingerprint)} is confirmed but reached only ${safeQuote(entry.rung_reached)}; a confirmed record requires R3`,
      );
    }
    // A record may legitimately reach R3 locally and still be needs_validation
    // when its blocker is a deployment fact absent from source. What is
    // contradictory is reaching R3 while also claiming a sandbox capability
    // blocker: the capability was evidently available.
    if (
      fingerprintOk &&
      !context.confirmed.has(entry.fingerprint) &&
      CONFIRMABLE_RUNGS.has(entry.rung_reached) &&
      isVisibleText(entry.capability_blocker)
    ) {
      errors.push(
        `${base}.capability_blocker: ${safeQuote(entry.fingerprint)} reached ${safeQuote(entry.rung_reached)}, so a sandbox capability blocker cannot also hold; a deployment blocker belongs in the record's blockers`,
      );
    }
  });

  for (const fingerprint of context.confirmed) {
    if (!seen.has(fingerprint)) {
      errors.push(`$: confirmed fingerprint ${safeQuote(fingerprint)} has no reproduction-ladder entry`);
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// calibration-log.json
// ---------------------------------------------------------------------------

const CALIBRATION_KEYS = new Set([
  "fingerprint",
  "attacker_position",
  "pre_calibration_overall",
  "post_calibration_overall",
  "cap_applied",
  "stale_evidence",
  "checklist",
]);

function validateCalibrationLog(entries, context) {
  const errors = [];
  if (!expectArray(errors, entries, "calibration-log.json")) return errors;
  const seen = new Set();

  entries.forEach((entry, index) => {
    const base = `$[${index}]`;
    if (!isObject(entry)) {
      errors.push(`${base}: must be an object`);
      return;
    }
    requireKeys(errors, base, entry, [
      "fingerprint",
      "attacker_position",
      "pre_calibration_overall",
      "post_calibration_overall",
      "checklist",
    ]);
    rejectUnknownKeys(errors, base, entry, CALIBRATION_KEYS);

    const fingerprintOk = checkFingerprintRef(errors, context, `${base}.fingerprint`, entry.fingerprint, {
      mustBeConfirmed: true,
    });
    if (fingerprintOk) {
      if (seen.has(entry.fingerprint)) {
        errors.push(`${base}.fingerprint: duplicate entry for ${safeQuote(entry.fingerprint)}`);
      } else {
        seen.add(entry.fingerprint);
      }
    }

    if (!ATTACKER_POSITIONS.has(entry.attacker_position)) {
      errors.push(`${base}.attacker_position: invalid ${safeQuote(entry.attacker_position)}`);
    }

    const preRank = SEVERITY_RANK.get(entry.pre_calibration_overall);
    const postRank = SEVERITY_RANK.get(entry.post_calibration_overall);
    if (preRank === undefined) {
      errors.push(`${base}.pre_calibration_overall: invalid ${safeQuote(entry.pre_calibration_overall)}`);
    }
    if (postRank === undefined) {
      errors.push(`${base}.post_calibration_overall: invalid ${safeQuote(entry.post_calibration_overall)}`);
    }
    if (preRank !== undefined && postRank !== undefined && postRank > preRank) {
      errors.push(
        `${base}.post_calibration_overall: calibration may only lower severity (${safeQuote(entry.pre_calibration_overall)} -> ${safeQuote(entry.post_calibration_overall)})`,
      );
    }

    if (fingerprintOk && postRank !== undefined) {
      const record = context.fingerprints.get(entry.fingerprint);
      const recorded = isObject(record.severity) ? record.severity.overall_severity : undefined;
      if (recorded !== entry.post_calibration_overall) {
        errors.push(
          `${base}.post_calibration_overall: ${safeQuote(entry.post_calibration_overall)} disagrees with findings.json severity.overall_severity ${safeQuote(recorded)}`,
        );
      }
    }

    if (hasOwn(entry, "stale_evidence") && typeof entry.stale_evidence !== "boolean") {
      errors.push(`${base}.stale_evidence: must be a boolean`);
    }

    const applied = new Set();
    const unknowns = [];
    if (!Array.isArray(entry.checklist) || entry.checklist.length === 0) {
      errors.push(`${base}.checklist: must be a non-empty array`);
    } else {
      const rulesSeen = new Set();
      entry.checklist.forEach((item, i) => {
        const itemBase = `${base}.checklist[${i}]`;
        if (!isObject(item)) {
          errors.push(`${itemBase}: must be an object`);
          return;
        }
        rejectUnknownKeys(errors, itemBase, item, new Set(["rule", "outcome", "reason"]));
        if (!CALIBRATION_RULES.has(item.rule)) {
          errors.push(`${itemBase}.rule: unknown calibration rule ${safeQuote(item.rule)}`);
        } else if (rulesSeen.has(item.rule)) {
          errors.push(`${itemBase}.rule: duplicate ${safeQuote(item.rule)}`);
        } else {
          rulesSeen.add(item.rule);
        }
        if (!CHECKLIST_OUTCOMES.has(item.outcome)) {
          errors.push(`${itemBase}.outcome: invalid ${safeQuote(item.outcome)}`);
          return;
        }
        if (item.outcome !== "does_not_apply" && !isVisibleText(item.reason)) {
          errors.push(`${itemBase}.reason: required when the outcome is ${safeQuote(item.outcome)}`);
        }
        if (item.outcome === "applies") applied.add(item.rule);
        if (item.outcome === "unknown") unknowns.push(item.rule);
      });
    }

    if (hasOwn(entry, "cap_applied") && entry.cap_applied !== null) {
      if (!CAP_CEILING.has(entry.cap_applied)) {
        errors.push(`${base}.cap_applied: ${safeQuote(entry.cap_applied)} is not a capping rule`);
      } else {
        if (!applied.has(entry.cap_applied)) {
          errors.push(
            `${base}.cap_applied: ${safeQuote(entry.cap_applied)} is not marked "applies" in the checklist`,
          );
        }
        const ceiling = SEVERITY_RANK.get(CAP_CEILING.get(entry.cap_applied));
        if (postRank !== undefined && postRank > ceiling) {
          errors.push(
            `${base}.post_calibration_overall: ${safeQuote(entry.post_calibration_overall)} exceeds the ceiling of cap ${safeQuote(entry.cap_applied)}`,
          );
        }
      }
    }

    // The most restrictive cap that fired must be the one recorded.
    let strictest = null;
    let strictestRank = Infinity;
    for (const rule of applied) {
      if (!CAP_CEILING.has(rule)) continue;
      const rank = SEVERITY_RANK.get(CAP_CEILING.get(rule));
      if (rank < strictestRank) {
        strictestRank = rank;
        strictest = rule;
      }
    }
    if (strictest !== null) {
      const recordedCap = hasOwn(entry, "cap_applied") ? entry.cap_applied : null;
      const recordedRank = CAP_CEILING.has(recordedCap) ? SEVERITY_RANK.get(CAP_CEILING.get(recordedCap)) : Infinity;
      if (recordedRank > strictestRank) {
        errors.push(
          `${base}.cap_applied: ${safeQuote(strictest)} applies and is more restrictive than the recorded cap`,
        );
      }
      if (postRank !== undefined && postRank > strictestRank) {
        errors.push(
          `${base}.post_calibration_overall: exceeds the ceiling of the most restrictive applied cap ${safeQuote(strictest)}`,
        );
      }
    }

    if (unknowns.length > 0 && hasOwn(entry, "cap_applied") && unknowns.includes(entry.cap_applied)) {
      errors.push(`${base}.cap_applied: a cap with an "unknown" outcome must not be applied`);
    }
  });

  for (const fingerprint of context.confirmed) {
    if (!seen.has(fingerprint)) {
      errors.push(`$: confirmed fingerprint ${safeQuote(fingerprint)} has no calibration-log entry`);
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// chains.json
// ---------------------------------------------------------------------------

const CHAIN_DOC_KEYS = new Set(["run_id", "source_ref", "chains", "correlations"]);
const CHAIN_KEYS = new Set([
  "chain_id",
  "title",
  "verdict",
  "links",
  "entry_principal",
  "user_interaction",
  "composite_result",
  "composite_severity",
  "blockers",
  "break_points",
  "counts_as_finding",
]);
const LINK_KEYS = new Set([
  "order",
  "fingerprint",
  "role",
  "provides",
  "requires",
  "unreachable_without_prior",
  "link_status",
]);

function validateChains(document, context) {
  const errors = [];
  if (!isObject(document)) {
    errors.push("chains.json: must be a JSON object");
    return errors;
  }
  rejectUnknownKeys(errors, "$", document, CHAIN_DOC_KEYS);
  requireKeys(errors, "$", document, ["run_id", "source_ref", "chains"]);
  if (!isVisibleText(document.run_id)) errors.push("$.run_id: must be non-empty text");
  if (!isVisibleText(document.source_ref)) errors.push("$.source_ref: must be non-empty text");

  if (!expectArray(errors, document.chains, "$.chains")) return errors;
  const seenChainIds = new Set();
  const seenSequences = new Set();

  document.chains.forEach((chain, index) => {
    const base = `$.chains[${index}]`;
    if (!isObject(chain)) {
      errors.push(`${base}: must be an object`);
      return;
    }
    requireKeys(errors, base, chain, [
      "chain_id",
      "title",
      "verdict",
      "links",
      "entry_principal",
      "composite_result",
      "counts_as_finding",
    ]);
    rejectUnknownKeys(errors, base, chain, CHAIN_KEYS);

    if (typeof chain.chain_id !== "string" || !CHAIN_ID_PATTERN.test(chain.chain_id)) {
      errors.push(`${base}.chain_id: expected chain-<hex>, got ${safeQuote(chain.chain_id)}`);
    } else if (seenChainIds.has(chain.chain_id)) {
      errors.push(`${base}.chain_id: duplicate ${safeQuote(chain.chain_id)}`);
    } else {
      seenChainIds.add(chain.chain_id);
    }
    if (context.fingerprints.has(chain.chain_id)) {
      errors.push(`${base}.chain_id: collides with a findings.json fingerprint`);
    }

    if (!isVisibleText(chain.title)) errors.push(`${base}.title: must be non-empty text`);
    if (!isVisibleText(chain.entry_principal)) errors.push(`${base}.entry_principal: must be non-empty text`);
    if (!isVisibleText(chain.composite_result)) errors.push(`${base}.composite_result: must be non-empty text`);
    if (!CHAIN_VERDICTS.has(chain.verdict)) errors.push(`${base}.verdict: invalid ${safeQuote(chain.verdict)}`);
    if (chain.counts_as_finding !== false) {
      errors.push(`${base}.counts_as_finding: must be false; a chain is never a finding`);
    }
    if (hasOwn(chain, "user_interaction") && !USER_INTERACTION.has(chain.user_interaction)) {
      errors.push(`${base}.user_interaction: invalid ${safeQuote(chain.user_interaction)}`);
    }

    if (!Array.isArray(chain.links) || chain.links.length < 2) {
      errors.push(`${base}.links: a chain requires at least two links`);
      return;
    }

    const statuses = [];
    const sequence = [];
    chain.links.forEach((link, i) => {
      const linkBase = `${base}.links[${i}]`;
      if (!isObject(link)) {
        errors.push(`${linkBase}: must be an object`);
        return;
      }
      requireKeys(errors, linkBase, link, ["order", "fingerprint", "role", "link_status"]);
      rejectUnknownKeys(errors, linkBase, link, LINK_KEYS);

      if (link.order !== i + 1) errors.push(`${linkBase}.order: expected ${i + 1}, got ${safeQuote(link.order)}`);
      if (!LINK_ROLES.has(link.role)) errors.push(`${linkBase}.role: invalid ${safeQuote(link.role)}`);
      if (i === 0 && link.role !== "entry") errors.push(`${linkBase}.role: the first link must be the entry`);
      if (i > 0 && link.role === "entry") errors.push(`${linkBase}.role: only the first link may be the entry`);
      if (i === chain.links.length - 1 && link.role !== "terminal") {
        errors.push(`${linkBase}.role: the last link must be the terminal`);
      }
      if (!LINK_STATUSES.has(link.link_status)) {
        errors.push(`${linkBase}.link_status: invalid ${safeQuote(link.link_status)}`);
      } else {
        statuses.push(link.link_status);
      }

      if (checkFingerprintRef(errors, context, `${linkBase}.fingerprint`, link.fingerprint, { mustBeConfirmed: true })) {
        sequence.push(link.fingerprint);
      }

      if (i === 0) {
        if (!isVisibleText(link.provides)) {
          errors.push(`${linkBase}.provides: the entry link must state the post-condition it establishes`);
        }
      } else {
        if (!isVisibleText(link.requires)) {
          errors.push(`${linkBase}.requires: a non-entry link must state the precondition the prior link satisfies`);
        }
        if (link.unreachable_without_prior !== true) {
          errors.push(
            `${linkBase}.unreachable_without_prior: must be true; if the precondition is reachable without the prior link there is no chain`,
          );
        }
      }
    });

    const fingerprintsInChain = new Set(sequence);
    if (fingerprintsInChain.size !== sequence.length) {
      errors.push(`${base}.links: the same fingerprint appears more than once`);
    }
    if (sequence.length === chain.links.length) {
      const key = sequence.join("|");
      if (seenSequences.has(key)) {
        errors.push(`${base}.links: duplicate chain; the same ordered link sequence is already recorded`);
      } else {
        seenSequences.add(key);
      }
    }

    if (statuses.length === chain.links.length) {
      const allSupported = statuses.every((status) => status === "supported");
      const allRefuted = statuses.every((status) => status === "refuted");
      if (chain.verdict === "confirmed" && !allSupported) {
        errors.push(`${base}.verdict: confirmed requires every link_status to be supported`);
      }
      if (chain.verdict === "refuted" && !allRefuted) {
        errors.push(`${base}.verdict: refuted requires every link_status to be refuted`);
      }
      if (chain.verdict === "open" && (allSupported || allRefuted)) {
        errors.push(`${base}.verdict: open is not available when every link agrees`);
      }
    }

    const severity = hasOwn(chain, "composite_severity") ? chain.composite_severity : null;
    if (chain.verdict === "confirmed") {
      if (!SEVERITY_RANK.has(severity)) {
        errors.push(`${base}.composite_severity: a confirmed chain requires a severity level`);
      } else {
        let strongestLink = -1;
        for (const fingerprint of sequence) {
          const record = context.fingerprints.get(fingerprint);
          const level = isObject(record) && isObject(record.severity) ? record.severity.overall_severity : undefined;
          if (SEVERITY_RANK.has(level)) strongestLink = Math.max(strongestLink, SEVERITY_RANK.get(level));
        }
        if (strongestLink >= 0 && SEVERITY_RANK.get(severity) <= strongestLink) {
          errors.push(
            `${base}.composite_severity: ${safeQuote(severity)} does not exceed the strongest link; emit no chain`,
          );
        }
      }
    } else if (severity !== null) {
      errors.push(`${base}.composite_severity: must be null unless the verdict is confirmed`);
    }

    if (chain.verdict === "open") {
      if (!Array.isArray(chain.blockers) || chain.blockers.length === 0) {
        errors.push(`${base}.blockers: an open chain must name its unestablished pivot`);
      }
    }
  });

  if (hasOwn(document, "correlations")) {
    if (!expectArray(errors, document.correlations, "$.correlations")) return errors;
    document.correlations.forEach((correlation, index) => {
      const base = `$.correlations[${index}]`;
      if (!isObject(correlation)) {
        errors.push(`${base}: must be an object`);
        return;
      }
      rejectUnknownKeys(errors, base, correlation, new Set(["kind", "key", "members", "status"]));
      requireKeys(errors, base, correlation, ["kind", "key", "members", "status"]);
      if (!CORRELATION_KINDS.has(correlation.kind)) errors.push(`${base}.kind: invalid ${safeQuote(correlation.kind)}`);
      if (!isVisibleText(correlation.key)) errors.push(`${base}.key: must be non-empty text`);
      if (correlation.status !== "observation_only") {
        errors.push(`${base}.status: must be "observation_only"; a correlation is never evidence`);
      }
      if (!Array.isArray(correlation.members) || correlation.members.length < 2) {
        errors.push(`${base}.members: a correlation needs at least two members`);
      } else {
        correlation.members.forEach((fp, i) => {
          checkFingerprintRef(errors, context, `${base}.members[${i}]`, fp);
        });
      }
    });
  }

  return errors;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const ARTIFACTS = [
  { file: "history-leads.json", validate: validateHistoryLeads },
  { file: "reflection-log.json", validate: validateReflectionLog },
  { file: "reproduction-ladder.json", validate: validateReproductionLadder },
  { file: "calibration-log.json", validate: validateCalibrationLog },
  { file: "chains.json", validate: validateChains },
];

const NARRATIVE_ARTIFACTS = ["threat-model.md", "dependencies.json"];

function run(outputDir) {
  if (typeof outputDir !== "string" || outputDir.length === 0) {
    console.error("Usage: node validate-companion-artifacts.cjs <output-dir>");
    return 1;
  }

  let stat;
  try {
    stat = fs.statSync(outputDir);
  } catch {
    console.error(`Failed to read output directory: ${safeQuote(outputDir)} could not be opened`);
    return 1;
  }
  if (!stat.isDirectory()) {
    console.error("Failed to read output directory: not a directory");
    return 1;
  }

  const findingsPath = path.join(outputDir, "findings.json");
  let findings;
  try {
    findings = loadJson(findingsPath);
  } catch (error) {
    const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
    console.error(`Failed to read findings.json: ${reason}`);
    return 1;
  }
  if (!Array.isArray(findings)) {
    console.error("Failed to read findings.json: expected a JSON array");
    return 1;
  }

  const ledgerPath = path.join(outputDir, "coverage-ledger.json");
  let ledger = null;
  if (fs.existsSync(ledgerPath)) {
    try {
      ledger = loadJson(ledgerPath);
    } catch (error) {
      const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
      console.error(`Failed to read coverage-ledger.json: ${reason}`);
      return 1;
    }
    if (!Array.isArray(ledger)) {
      console.error("Failed to read coverage-ledger.json: expected a JSON array");
      return 1;
    }
  }

  const context = buildContext(findings, ledger);
  const allErrors = [];
  const present = [];
  const absent = [];

  for (const artifact of ARTIFACTS) {
    const file = path.join(outputDir, artifact.file);
    if (!fs.existsSync(file)) {
      absent.push(artifact.file);
      continue;
    }
    present.push(artifact.file);
    let document;
    try {
      document = loadJson(file);
    } catch (error) {
      const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
      allErrors.push(`${artifact.file}: ${reason}`);
      continue;
    }
    let errors;
    try {
      errors = artifact.validate(document, context);
    } catch {
      allErrors.push(`${artifact.file}: unexpected validation error`);
      continue;
    }
    for (const message of errors) allErrors.push(`${artifact.file} ${message}`);
  }

  for (const file of NARRATIVE_ARTIFACTS) {
    if (!fs.existsSync(path.join(outputDir, file))) absent.push(file);
  }

  const capped = allErrors.slice(0, LIMITS.validationErrors);
  for (const message of capped) console.error("ERROR:", escapeUnsafeDiagnosticCharacters(message));
  if (allErrors.length > 0) {
    const cap = allErrors.length > LIMITS.validationErrors ? `; output capped at ${LIMITS.validationErrors}` : "";
    console.error(`FAIL: ${allErrors.length} validation error(s)${cap}`);
    return 1;
  }

  const summary = present.length > 0 ? present.join(", ") : "none";
  console.log(`PASS: ${present.length} companion artifact(s) valid (${summary})`);
  if (absent.length > 0) console.log(`NOTE: not produced by this run: ${absent.join(", ")}`);
  return 0;
}

module.exports = {
  LIMITS,
  CALIBRATION_RULES,
  CAP_CEILING,
  RUNG_RANK,
  buildContext,
  isSafeRepoPath,
  validateCalibrationLog,
  validateChains,
  validateHistoryLeads,
  validateReflectionLog,
  validateReproductionLadder,
  run,
};

if (require.main === module) process.exit(run(process.argv[2]));
