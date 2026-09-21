"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  CALIBRATION_RULES,
  CAP_CEILING,
  buildContext,
  isSafeRepoPath,
  validateCalibrationLog,
  validateChains,
  validateHistoryLeads,
  validateReflectionLog,
  validateReproductionLadder,
  run,
} = require("./validate-companion-artifacts.cjs");

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const confirmedRecord = (fingerprint, overall = "medium") => ({
  verdict: "confirmed",
  fingerprint,
  title: `finding ${fingerprint}`,
  severity: {
    likelihood: { score: overall, reason: "r" },
    impact: { score: overall, reason: "r" },
    overall_severity: overall,
  },
});

const pendingRecord = (fingerprint) => ({
  verdict: "needs_validation",
  fingerprint,
  title: `pending ${fingerprint}`,
});

const rejectedRecord = (fingerprint) => ({
  verdict: "rejected",
  fingerprint,
  title: `rejected ${fingerprint}`,
});

const unit = (coverageId) => ({ coverage_id: coverageId });

function ctx(findings = [], ledger = []) {
  return buildContext(findings, ledger);
}

const REV_A = "a".repeat(40);
const REV_B = "b".repeat(40);

const goodLead = (over = {}) => ({
  lead_id: "hl-0001",
  coverage_ids: ["cov-1"],
  signal: "guard_removed",
  fix_rev: REV_A,
  regression_rev: REV_B,
  rev_date: "2023-04-11T09:22:05+00:00",
  rev_subject: "sanitize redirect target",
  historical_paths: ["src/http/redirect.go:118"],
  invariant: "redirect target must resolve inside the allowlist",
  present_anchor: { path: "src/http/redirect.go", symbol: "writeRedirect", status: "enforcement_absent" },
  present_status: "live",
  hypothesis: "writeRedirect no longer validates the target host",
  confidence_source: "source_read",
  history_status: "full",
  linked_fingerprints: [],
  disposition: "open",
  ...over,
});

const goodInsight = (over = {}) => ({
  insight_id: "rl-0001",
  wave: 1,
  class: "boundary_fact",
  target: { coverage_ids: ["cov-1"], paths: ["src/http/redirect.go"], fingerprints: [] },
  insight: "every route registered in routes/index.ts passes through requireScope",
  evidence_paths: ["middleware/authz.ts"],
  source: "hunter_result",
  directive: "note",
  scope: "subsystem",
  status: "active",
  superseded_by: null,
  ...over,
});

const goodRung = (over = {}) => ({
  fingerprint: "fp-a",
  rung_reached: "R3",
  rung_attempted: "R3",
  evidence_channel: "a",
  environment_tier: "hardened_container",
  capability_blocker: null,
  ...over,
});

const goodCalibration = (over = {}) => ({
  fingerprint: "fp-a",
  attacker_position: "external",
  pre_calibration_overall: "high",
  post_calibration_overall: "medium",
  cap_applied: "self_contained_blast",
  stale_evidence: false,
  checklist: [
    { rule: "self_contained_blast", outcome: "applies", reason: "result stays inside the triggering tenant" },
    { rule: "local_vector", outcome: "does_not_apply" },
  ],
  ...over,
});

const goodChainDoc = (over = {}) => ({
  run_id: "run-1",
  source_ref: "deadbeef",
  chains: [
    {
      chain_id: "chain-0123abcd",
      title: "Exploit chain: tenant takeover via header override then export",
      verdict: "confirmed",
      links: [
        {
          order: 1,
          fingerprint: "fp-a",
          role: "entry",
          provides: "attacker controls the tenant id in the request context",
          link_status: "supported",
        },
        {
          order: 2,
          fingerprint: "fp-b",
          role: "terminal",
          requires: "a tenant id the caller does not own",
          unreachable_without_prior: true,
          link_status: "supported",
        },
      ],
      entry_principal: "unauthenticated network client",
      user_interaction: "none",
      composite_result: "full cross-tenant export of another tenant's records",
      composite_severity: "high",
      blockers: [],
      break_points: ["fp-a"],
      counts_as_finding: false,
    },
  ],
  correlations: [],
  ...over,
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

test("isSafeRepoPath rejects absolute, traversing and drive-letter paths", () => {
  assert.equal(isSafeRepoPath("src/app.ts"), true);
  assert.equal(isSafeRepoPath("/etc/passwd"), false);
  assert.equal(isSafeRepoPath("../secrets"), false);
  assert.equal(isSafeRepoPath("C:/windows"), false);
  assert.equal(isSafeRepoPath("~/id_rsa"), false);
  assert.equal(isSafeRepoPath("a/./b"), false);
});

test("every capping rule has a ceiling and every ceiling names a known rule", () => {
  for (const rule of CAP_CEILING.keys()) assert.ok(CALIBRATION_RULES.has(rule), `${rule} unknown`);
  assert.ok(CAP_CEILING.size > 0);
});

// ---------------------------------------------------------------------------
// history-leads.json
// ---------------------------------------------------------------------------

test("history leads: a well-formed lead validates", () => {
  const context = ctx([], [unit("cov-1")]);
  assert.deepEqual(validateHistoryLeads([goodLead()], context), []);
});

test("history leads: rejects a non-array document", () => {
  const errors = validateHistoryLeads({}, ctx());
  assert.match(errors.join("\n"), /must be a JSON array/);
});

test("history leads: rejects a short commit id", () => {
  const errors = validateHistoryLeads([goodLead({ fix_rev: "abc1234" })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /fix_rev: expected a 40-character/);
});

test("history leads: rejects an unknown signal", () => {
  const errors = validateHistoryLeads([goodLead({ signal: "vibes" })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /signal: invalid/);
});

test("history leads: rejects a coverage ID that is not in the ledger", () => {
  const errors = validateHistoryLeads([goodLead({ coverage_ids: ["cov-missing"] })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /is not in coverage-ledger\.json/);
});

test("history leads: flags a missing ledger when coverage IDs are referenced", () => {
  const errors = validateHistoryLeads([goodLead()], buildContext([], null));
  assert.match(errors.join("\n"), /coverage-ledger\.json is required/);
});

test("history leads: rejects a duplicate lead_id", () => {
  const errors = validateHistoryLeads([goodLead(), goodLead()], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /duplicate/);
});

test("history leads: a lead may not carry a severity", () => {
  const lead = goodLead();
  lead.severity = "high";
  const errors = validateHistoryLeads([lead], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /must not carry severity/);
});

test("history leads: rejects an unknown property", () => {
  const errors = validateHistoryLeads([goodLead({ secret_value: "x" })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /must not carry secret|unknown property/);
});

test("history leads: a linked fingerprint must exist in findings.json", () => {
  const context = ctx([confirmedRecord("fp-a")], [unit("cov-1")]);
  const errors = validateHistoryLeads([goodLead({ linked_fingerprints: ["fp-ghost"] })], context);
  assert.match(errors.join("\n"), /is not in findings\.json/);
});

test("history leads: rejects an absolute historical path", () => {
  const errors = validateHistoryLeads([goodLead({ historical_paths: ["/etc/shadow:1"] })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /repository-relative path/);
});

// ---------------------------------------------------------------------------
// reflection-log.json
// ---------------------------------------------------------------------------

test("reflection log: a well-formed insight validates", () => {
  assert.deepEqual(validateReflectionLog([goodInsight()], ctx([], [unit("cov-1")])), []);
});

test("reflection log: rejects an unknown class", () => {
  const errors = validateReflectionLog([goodInsight({ class: "hunch" })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /class: invalid/);
});

test("reflection log: an insight must name at least one target", () => {
  const errors = validateReflectionLog(
    [goodInsight({ target: { coverage_ids: [], paths: [], fingerprints: [] } })],
    ctx([], [unit("cov-1")]),
  );
  assert.match(errors.join("\n"), /must name at least one/);
});

test("reflection log: a superseded insight must name its replacement", () => {
  const errors = validateReflectionLog([goodInsight({ status: "superseded" })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /superseded_by/);
});

test("reflection log: an insight cannot supersede itself", () => {
  const errors = validateReflectionLog(
    [goodInsight({ status: "superseded", superseded_by: "rl-0001" })],
    ctx([], [unit("cov-1")]),
  );
  assert.match(errors.join("\n"), /cannot supersede itself/);
});

test("reflection log: superseded_by must be null while active", () => {
  const errors = validateReflectionLog(
    [goodInsight({ superseded_by: "rl-0002" }), goodInsight({ insight_id: "rl-0002" })],
    ctx([], [unit("cov-1")]),
  );
  assert.match(errors.join("\n"), /must be null unless status is superseded/);
});

test("reflection log: an insight may not carry a payload", () => {
  const entry = goodInsight();
  entry.payload = "<script>";
  const errors = validateReflectionLog([entry], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /must not carry payload/);
});

// ---------------------------------------------------------------------------
// reproduction-ladder.json
// ---------------------------------------------------------------------------

test("reproduction ladder: a confirmed record at R3 validates", () => {
  const context = ctx([confirmedRecord("fp-a")]);
  assert.deepEqual(validateReproductionLadder([goodRung()], context), []);
});

test("reproduction ladder: a confirmed record below R3 fails", () => {
  const context = ctx([confirmedRecord("fp-a")]);
  const errors = validateReproductionLadder(
    [goodRung({ rung_reached: "R1", rung_attempted: "R3", capability_blocker: "no runsc runtime" })],
    context,
  );
  assert.match(errors.join("\n"), /a confirmed record requires R3/);
});

test("reproduction ladder: every confirmed record needs an entry", () => {
  const context = ctx([confirmedRecord("fp-a"), confirmedRecord("fp-b")]);
  const errors = validateReproductionLadder([goodRung()], context);
  assert.match(errors.join("\n"), /fp-b.*has no reproduction-ladder entry/s);
});

test("reproduction ladder: a needs_validation record may sit at R3 with a deployment blocker", () => {
  const context = ctx([pendingRecord("fp-p")]);
  assert.deepEqual(validateReproductionLadder([goodRung({ fingerprint: "fp-p" })], context), []);
});

test("reproduction ladder: R3 plus a sandbox capability blocker is contradictory", () => {
  const context = ctx([pendingRecord("fp-p")]);
  const errors = validateReproductionLadder(
    [goodRung({ fingerprint: "fp-p", capability_blocker: "no runsc runtime registered" })],
    context,
  );
  assert.match(errors.join("\n"), /a sandbox capability blocker cannot also hold/);
});

test("history leads: a resolved lead may record an empty coverage_ids array", () => {
  const lead = goodLead({ present_status: "resolved_by_source", disposition: "dropped", coverage_ids: [] });
  assert.deepEqual(validateHistoryLeads([lead], ctx([], [unit("cov-1")])), []);
});

test("history leads: a live lead must be linked to a unit", () => {
  const errors = validateHistoryLeads([goodLead({ coverage_ids: [] })], ctx([], [unit("cov-1")]));
  assert.match(errors.join("\n"), /must be a non-empty array of coverage IDs/);
});

test("reproduction ladder: a missed rung requires a capability blocker", () => {
  const context = ctx([pendingRecord("fp-p")]);
  const errors = validateReproductionLadder(
    [goodRung({ fingerprint: "fp-p", rung_reached: "R1", rung_attempted: "R3", capability_blocker: null })],
    context,
  );
  assert.match(errors.join("\n"), /capability_blocker: required/);
});

test("reproduction ladder: the static tier cannot reach an executing rung", () => {
  const context = ctx([pendingRecord("fp-p")]);
  const errors = validateReproductionLadder(
    [
      goodRung({
        fingerprint: "fp-p",
        rung_reached: "R2",
        rung_attempted: "R3",
        environment_tier: "static",
        capability_blocker: "no sandbox available",
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /unreachable on the static tier/);
});

test("reproduction ladder: a rung at or above R1 requires an evidence channel", () => {
  const context = ctx([confirmedRecord("fp-a")]);
  const errors = validateReproductionLadder([goodRung({ evidence_channel: null })], context);
  assert.match(errors.join("\n"), /requires a reached-sink evidence channel/);
});

test("reproduction ladder: rung_reached may not exceed rung_attempted", () => {
  const context = ctx([confirmedRecord("fp-a")]);
  const errors = validateReproductionLadder([goodRung({ rung_attempted: "R1" })], context);
  assert.match(errors.join("\n"), /cannot exceed rung_attempted/);
});

// ---------------------------------------------------------------------------
// calibration-log.json
// ---------------------------------------------------------------------------

test("calibration log: a downward calibration validates", () => {
  const context = ctx([confirmedRecord("fp-a", "medium")]);
  assert.deepEqual(validateCalibrationLog([goodCalibration()], context), []);
});

test("calibration log: severity may never be raised", () => {
  const context = ctx([confirmedRecord("fp-a", "critical")]);
  const errors = validateCalibrationLog(
    [
      goodCalibration({
        pre_calibration_overall: "medium",
        post_calibration_overall: "critical",
        cap_applied: null,
        checklist: [{ rule: "local_vector", outcome: "does_not_apply" }],
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /may only lower severity/);
});

test("calibration log: post severity must match findings.json", () => {
  const context = ctx([confirmedRecord("fp-a", "high")]);
  const errors = validateCalibrationLog([goodCalibration()], context);
  assert.match(errors.join("\n"), /disagrees with findings\.json/);
});

test("calibration log: an applied cap must be marked applies in the checklist", () => {
  const context = ctx([confirmedRecord("fp-a", "medium")]);
  const errors = validateCalibrationLog(
    [
      goodCalibration({
        checklist: [{ rule: "self_contained_blast", outcome: "does_not_apply" }],
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /not marked "applies"/);
});

test("calibration log: severity may not exceed the applied cap's ceiling", () => {
  const context = ctx([confirmedRecord("fp-a", "high")]);
  const errors = validateCalibrationLog(
    [goodCalibration({ pre_calibration_overall: "critical", post_calibration_overall: "high" })],
    context,
  );
  assert.match(errors.join("\n"), /exceeds the ceiling of cap/);
});

test("calibration log: the most restrictive applied cap must be the recorded one", () => {
  const context = ctx([confirmedRecord("fp-a", "medium")]);
  const errors = validateCalibrationLog(
    [
      goodCalibration({
        cap_applied: "exposure_internal",
        checklist: [
          { rule: "exposure_internal", outcome: "applies", reason: "internal only" },
          { rule: "self_contained_blast", outcome: "applies", reason: "own tenant only" },
        ],
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /more restrictive than the recorded cap/);
});

test("calibration log: a cap with an unknown outcome must not be applied", () => {
  const context = ctx([confirmedRecord("fp-a", "medium")]);
  const errors = validateCalibrationLog(
    [
      goodCalibration({
        checklist: [{ rule: "self_contained_blast", outcome: "unknown", reason: "could not establish tenancy" }],
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /a cap with an "unknown" outcome must not be applied/);
});

test("calibration log: only confirmed records may be calibrated", () => {
  const context = ctx([pendingRecord("fp-p")]);
  const errors = validateCalibrationLog([goodCalibration({ fingerprint: "fp-p" })], context);
  assert.match(errors.join("\n"), /expected confirmed/);
});

test("calibration log: rejects an unknown rule name", () => {
  const context = ctx([confirmedRecord("fp-a", "medium")]);
  const errors = validateCalibrationLog(
    [
      goodCalibration({
        cap_applied: null,
        checklist: [{ rule: "looks_scary", outcome: "applies", reason: "gut feeling" }],
      }),
    ],
    context,
  );
  assert.match(errors.join("\n"), /unknown calibration rule/);
});

test("calibration log: every confirmed record needs an entry", () => {
  const context = ctx([confirmedRecord("fp-a", "medium"), confirmedRecord("fp-b", "low")]);
  const errors = validateCalibrationLog([goodCalibration()], context);
  assert.match(errors.join("\n"), /fp-b.*has no calibration-log entry/s);
});

// ---------------------------------------------------------------------------
// chains.json
// ---------------------------------------------------------------------------

function chainContext() {
  return ctx([confirmedRecord("fp-a", "medium"), confirmedRecord("fp-b", "medium"), pendingRecord("fp-p")]);
}

test("chains: a well-formed confirmed chain validates", () => {
  assert.deepEqual(validateChains(goodChainDoc(), chainContext()), []);
});

test("chains: counts_as_finding must be false", () => {
  const doc = goodChainDoc();
  doc.chains[0].counts_as_finding = true;
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /a chain is never a finding/);
});

test("chains: a link must be a confirmed record", () => {
  const doc = goodChainDoc();
  doc.chains[0].links[1].fingerprint = "fp-p";
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /expected confirmed/);
});

test("chains: composite severity must exceed the strongest link", () => {
  const doc = goodChainDoc();
  doc.chains[0].composite_severity = "medium";
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /does not exceed the strongest link/);
});

test("chains: a non-confirmed chain carries no severity", () => {
  const doc = goodChainDoc();
  doc.chains[0].verdict = "open";
  doc.chains[0].links[1].link_status = "open";
  doc.chains[0].blockers = ["the export handler's tenant check was not established"];
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /must be null unless the verdict is confirmed/);
});

test("chains: an open chain must name a blocker", () => {
  const doc = goodChainDoc();
  doc.chains[0].verdict = "open";
  doc.chains[0].links[1].link_status = "open";
  doc.chains[0].composite_severity = null;
  doc.chains[0].blockers = [];
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /must name its unestablished pivot/);
});

test("chains: confirmed requires every link supported", () => {
  const doc = goodChainDoc();
  doc.chains[0].links[1].link_status = "open";
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /confirmed requires every link_status to be supported/);
});

test("chains: a non-entry link must be unreachable without its predecessor", () => {
  const doc = goodChainDoc();
  doc.chains[0].links[1].unreachable_without_prior = false;
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /there is no chain/);
});

test("chains: a chain needs at least two links", () => {
  const doc = goodChainDoc();
  doc.chains[0].links = [doc.chains[0].links[0]];
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /at least two links/);
});

test("chains: link order must be contiguous from one", () => {
  const doc = goodChainDoc();
  doc.chains[0].links[1].order = 5;
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /order: expected 2/);
});

test("chains: the first link must be the entry and the last the terminal", () => {
  const doc = goodChainDoc();
  doc.chains[0].links[0].role = "pivot";
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /the first link must be the entry/);
});

test("chains: the same ordered sequence may not be recorded twice", () => {
  const doc = goodChainDoc();
  const copy = JSON.parse(JSON.stringify(doc.chains[0]));
  copy.chain_id = "chain-beefbeef";
  doc.chains.push(copy);
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /duplicate chain/);
});

test("chains: a chain_id may not collide with a fingerprint", () => {
  const doc = goodChainDoc();
  doc.chains[0].chain_id = "chain-0123abcd";
  const context = ctx([confirmedRecord("chain-0123abcd"), confirmedRecord("fp-a"), confirmedRecord("fp-b")]);
  const errors = validateChains(doc, context);
  assert.match(errors.join("\n"), /collides with a findings\.json fingerprint/);
});

test("chains: a correlation is observation-only", () => {
  const doc = goodChainDoc({
    correlations: [{ kind: "shared_symbol", key: "writeRedirect", members: ["fp-a", "fp-b"], status: "evidence" }],
  });
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /never evidence/);
});

test("chains: a correlation needs at least two members", () => {
  const doc = goodChainDoc({
    correlations: [{ kind: "shared_file", key: "src/a.ts", members: ["fp-a"], status: "observation_only" }],
  });
  const errors = validateChains(doc, chainContext());
  assert.match(errors.join("\n"), /at least two members/);
});

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function withOutputDir(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sam-"));
  try {
    for (const [name, value] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), typeof value === "string" ? value : JSON.stringify(value, null, 2));
    }
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function quiet(fn) {
  const err = console.error;
  const log = console.log;
  const lines = [];
  console.error = (...args) => lines.push(args.join(" "));
  console.log = (...args) => lines.push(args.join(" "));
  try {
    return { code: fn(), output: lines.join("\n") };
  } finally {
    console.error = err;
    console.log = log;
  }
}

test("CLI: passes with no companion artifacts present", () => {
  withOutputDir({ "findings.json": [] }, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 0);
    assert.match(output, /PASS: 0 companion artifact/);
    assert.match(output, /NOTE: not produced by this run/);
  });
});

test("CLI: fails without findings.json", () => {
  withOutputDir({}, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 1);
    assert.match(output, /Failed to read findings\.json/);
  });
});

test("CLI: fails when findings.json is not an array", () => {
  withOutputDir({ "findings.json": { verdict: "confirmed" } }, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 1);
    assert.match(output, /expected a JSON array/);
  });
});

test("CLI: validates a complete, consistent run", () => {
  const files = {
    "findings.json": [confirmedRecord("fp-a", "medium"), confirmedRecord("fp-b", "medium")],
    "coverage-ledger.json": [unit("cov-1")],
    "history-leads.json": [goodLead()],
    "reflection-log.json": [goodInsight()],
    "reproduction-ladder.json": [goodRung(), goodRung({ fingerprint: "fp-b" })],
    "calibration-log.json": [
      goodCalibration(),
      goodCalibration({ fingerprint: "fp-b", pre_calibration_overall: "medium" }),
    ],
    "chains.json": goodChainDoc(),
  };
  withOutputDir(files, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 0, output);
    assert.match(output, /PASS: 5 companion artifact/);
  });
});

test("CLI: surfaces a cross-artifact inconsistency", () => {
  const files = {
    "findings.json": [confirmedRecord("fp-a", "medium")],
    "coverage-ledger.json": [unit("cov-1")],
    "reproduction-ladder.json": [goodRung({ rung_reached: "R1", capability_blocker: "no sandbox" })],
  };
  withOutputDir(files, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 1);
    assert.match(output, /a confirmed record requires R3/);
    assert.match(output, /FAIL: \d+ validation error/);
  });
});

test("CLI: rejects invalid JSON in a companion artifact", () => {
  withOutputDir({ "findings.json": [], "chains.json": "{not json" }, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 1);
    assert.match(output, /invalid JSON syntax/);
  });
});

test("CLI: rejects a rejected-verdict record used as a chain link", () => {
  const files = {
    "findings.json": [confirmedRecord("fp-a", "medium"), rejectedRecord("fp-b")],
    "chains.json": goodChainDoc(),
  };
  withOutputDir(files, (dir) => {
    const { code, output } = quiet(() => run(dir));
    assert.equal(code, 1);
    assert.match(output, /expected confirmed/);
  });
});

test("CLI: requires a directory, not a file", () => {
  withOutputDir({ "findings.json": [] }, (dir) => {
    const { code, output } = quiet(() => run(path.join(dir, "findings.json")));
    assert.equal(code, 1);
    assert.match(output, /not a directory/);
  });
});

test("CLI: prints usage without an argument", () => {
  const { code, output } = quiet(() => run(undefined));
  assert.equal(code, 1);
  assert.match(output, /Usage: node validate-companion-artifacts\.cjs/);
});
