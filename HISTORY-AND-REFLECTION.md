# Repository History and Inter-Wave Reflection

Read this in Phase 1 for history mining, and again between hunting waves in Phase 2 for reflection. In guidance mode, use only the section asked about and create no files.

Both mechanisms are lead sources. Neither produces a finding, assigns a severity, or closes a unit.

## Part A — History mining

The prior-run rules in `SKILL.md` cover previous *audit* runs. This part covers the *target's own* Git history: defects it has already fixed, guards it has since removed, and call sites that never received a fix its siblings did.

### Preconditions

Read-only, local, no network. Ordinary `git log` and `git blame` still refresh the index, take `index.lock`, and can trigger background maintenance — that is writing into the target, which anti-pattern 18 forbids. Use this exact prefix for every invocation, and treat `<target>` as the resolved repository root:

```sh
git --no-optional-locks -c gc.auto=0 -c core.fsmonitor=false -C <target> ...
```

Never `checkout`, `switch`, `restore`, `stash`, `worktree add`, `apply`, `notes`, `fetch`, or any command that writes to the working tree, the index, or the object store. The command listings below omit the prefix for readability; it is mandatory on every one of them.

Set `history_status` before anything else:

- `unsupported_vcs` — `git -C <target> rev-parse --git-dir` fails. Write an empty leads array, say so in the final coverage statement, and never fabricate history.
- `partial_shallow` — `rev-parse --is-shallow-repository` is `true`, or `.git/shallow` exists. Under this status, the absence of a historical hit is never evidence of cleanliness.
- `full` — otherwise.

Bound the scan: `--no-merges`, `--since` (default 5 years), `--max-count` (default 4000).

### Pass 1 — message screen

Cheap, before any diff is fetched:

```sh
git -C <target> log --no-merges --since=<S> --max-count=<N> --date=iso-strict \
  --format='%H%x1f%ad%x1f%an%x1f%s%x1f%b%x1e' -i \
  --grep='cve-[0-9]|ghsa-|security|vulnerab|exploit|attack|injection|xss|csrf|ssrf|traversal|deserial|prototype pollution|overflow|out.of.bounds|use.after.free|double free|race|toctou|sanitiz|escap|validat|bypass|auth|permission|privilege|tenant|leak|disclos|credential|secret|token|hardcode|regress|harden'
```

Add stack-specific terms from reconnaissance (`memcpy`, `unsafe`, `pickle`, `eval`, `sudo`, `chmod`, ORM raw-query helpers). Do not over-index on the message text: Pass 2 admits commits whose messages say nothing.

### Pass 2 — diff-signal screen

For each boundary-defining symbol recorded in a unit's `canonical_refs.boundary`:

```sh
git -C <target> log --no-merges -G'<boundary-symbol-regex>' --format='%H%x1f%ad%x1f%s' -- <unit starting_paths>
git -C <target> log --no-merges -S'<literal guard token>' --pickaxe-regex --format='%H' -- <path>
git -C <target> log -L <start>,<end>:<path> --format='%H%x1f%s'
git -C <target> log --diff-filter=D --format='%H%x1f%s' -- <path>
git -C <target> log --format='%H%x1f%s' -i --grep='^Revert'
git -C <target> show --stat --format='' <rev>
git -C <target> show -U5 --format='%H%x1f%s%x1f%b' <rev> -- <in-scope paths>
```

Apply the filters in this order, and fetch diffs only after them:

1. Drop commits touching only tests, docs, vendored dependencies, lockfiles, generated files, or prose.
2. Drop commits whose `--stat` exceeds roughly 2,000 changed lines, unless a pickaxe hit named a boundary symbol — large diffs are usually reformatting.
3. Rank what remains: reverted security fix > guard removed with no replacement > guard narrowed or weakened > fix inside a planned unit's `starting_paths` > fix elsewhere in an in-scope subsystem.

Diff signals worth extracting: an authorization or comparison call removed; a bounds or length check deleted; a loosened pattern, `==` relaxed to `startsWith`, an allowlist turned into a denylist; a sanitizer call dropped from one of several parallel call sites; `TODO`, `FIXME`, `XXX`, or `HACK` added next to a boundary; a default flipped from deny to allow; a timeout or limit removed; an error path changed from fail-closed to fail-open; a new caller added to an existing sink without the guard its peers carry.

### Turning a historical fix into a present-day hypothesis

Never report history as a finding. For each kept commit, work this order:

1. **State the invariant the fix established**, in one sentence.
2. **Locate the present-day enforcement point.** Use `git -C <target> blame -L <a>,<b> --porcelain -- <path>` with `--follow` or `-M` for renames, then read current source at the reviewed ref.
3. **Classify:** `still_enforced` (invariant holds at the same point) → record `resolved_by_source` and drop the lead; `enforcement_moved` → re-anchor the lead; `enforcement_absent` → live lead; `parallel_path` (the fixed call site holds but a sibling reaching the same sink does not) → live lead, highest value.
4. **Generalize once.** The same invariant at sibling call sites, sibling routes and handlers, the async, batch, export, or admin variant of the fixed path, and the same class in other subsystems. Each generalization is its own lead.
5. **Map each live lead to exactly one ledger unit.** Seed a new `planned` unit when none exists, exactly as the coverage critic's missing units are seeded. A lead never closes, blocks, or reopens a unit by itself. A lead that is not live — `resolved_by_source`, or one with no boundary unit to attach to — records an empty `coverage_ids` array; only a live lead must be linked.

### The removed-guard case

A fix commit `F` followed by a later commit `R` that removes or weakens the same guard is the highest-value class. Detect it with `git log -L` over the fixed range, `-S` on the guard token counting transitions, and `--grep='^Revert'` plus the `This reverts commit <sha>` body line. Record both `fix_rev` and `regression_rev`.

Then require present-source confirmation: the guard must be absent or weakened **at the reviewed ref**, established by reading source, not by reading the diff. A guard removed and later re-added, or replaced by an equivalent control elsewhere, is `resolved_by_source`. An unconfirmed removal is a lead, never a candidate — the hunter that owns the unit still has to establish the boundary and the result independently, under the normal candidate gate.

### Secrets found in history

Mandatory, no exceptions:

- Cite the full 40-character commit, the repository-relative path, and the line **of that revision** (`a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4:config/prod.yaml:14`), plus the detector class. Nothing else. `fix_rev` in the lead record is a 40-character lowercase hex commit; a short SHA fails validation.
- Never reproduce, excerpt, mask partially, hash, or derive from the credential value, in any file, prompt, artifact, ledger field, log, or report.
- Never run the credential and never test it against any service. Universal execution safety forbids it outright.
- Historical presence proves that the object existed in history. It does not prove present validity, present reachability, or a boundary violation. Emit at most a `needs_validation` record whose `blockers` name rotation status and current validity as owner-observed facts outside source, with a `validation_plan.deployment` asking the owner to confirm rotation, revocation, and the scope of any history rewrite. No severity.
- If the same value is still live in the worktree, that is an ordinary present-source candidate and takes precedence.

### `<output-dir>/history-leads.json`

A top-level JSON array. The parent is the only writer; hunters receive their own unit's leads inside the prompt.

```json
{
  "lead_id": "hl-0007",
  "coverage_ids": ["<coverage_id>"],
  "signal": "revert_of_security_fix|guard_removed|guard_weakened|parallel_path_unpatched|fix_pattern_generalized|secret_in_history",
  "fix_rev": "<40-hex>",
  "regression_rev": "<40-hex or null>",
  "rev_date": "2023-04-11T09:22:05+00:00",
  "rev_subject": "sanitize redirect target before 302",
  "historical_paths": ["src/http/redirect.go:118"],
  "invariant": "redirect target must resolve inside the configured origin allowlist",
  "present_anchor": { "path": "src/http/redirect.go", "symbol": "writeRedirect", "status": "enforcement_absent" },
  "present_status": "live|resolved_by_source|unverifiable",
  "hypothesis": "one sentence, present-day boundary claim, no severity",
  "confidence_source": "source_read|blame_only",
  "history_status": "full|partial_shallow|unsupported_vcs",
  "linked_fingerprints": [],
  "disposition": "open|assigned|superseded_by_finding|dropped",
  "disposition_reason": "..."
}
```

`linked_fingerprints` is written by the parent only after a hunter or verifier independently produces a candidate on that unit. It is provenance, never evidence. Record `history_lead_ids` as a parent bookkeeping field on the ledger unit; do not touch the unit's semantic fields, its state table, or `prior_status`.

## Part B — Inter-wave reflection

### When and at what cost

Once per completed hunter wave, in the same step where the parent consolidates results, **before** the reserved post-wave coverage critic is prompted.

Reflection is parent-side bookkeeping, not an agent invocation. It consumes no budget, so the critic and validation reserves are untouched. Never spend a reserved critic or verifier call on reflection, and never add a reflection agent to a `quick` run.

### Inputs

Only structured results: each closed unit's `disposition`, `reviewed_paths`, and per-check `invariant`, `method`, `result`; `unresolved`, `hardening`, `uncovered`; malformed or failed results; promotion blockers and sandbox capability failures; and, after Phases 3 and 5, each fingerprint's verifier outcome with its reason. Never raw agent prose — prose-only results are already rejected by anti-pattern 7.

### Insight classes

- `false_assumption` — a claimed sink is sanitized upstream at a named path. Record the upstream control's path and symbol.
- `blocked_method` — a check could not run. Record the exact blocker string so the next wave does not re-attempt it identically.
- `boundary_fact` — a load-bearing source fact established during the wave.
- `rejection_reason` — why a verifier rejected a fingerprint, generalized.
- `unit_shape` — a unit whose granularity was wrong: too broad to close, or splitting along a lifecycle mode.
- `missing_result` — a hunter returned nothing parseable for a unit, so an empty wave never passes as a silent zero-learning round.

### `<output-dir>/reflection-log.json`

An append-only JSON array. Parent-owned.

```json
{
  "insight_id": "rl-0031",
  "wave": 2,
  "class": "false_assumption|blocked_method|boundary_fact|rejection_reason|unit_shape|missing_result",
  "target": { "coverage_ids": ["..."], "paths": ["repo/relative/path"], "fingerprints": ["..."] },
  "insight": "one sentence, source-grounded, no payload, no severity, no secret",
  "evidence_paths": ["repo/relative/path"],
  "source": "hunter_result|verifier_result|parent_validation|promotion",
  "directive": "avoid|prefer|note",
  "scope": "unit|subsystem|run",
  "status": "active|superseded",
  "superseded_by": null
}
```

De-duplicate on `(class, target.coverage_ids ∪ target.paths, insight)`. `wave` and `insight_id` are metadata, not identity; re-running a wave must not double-append.

### Feeding the next wave without anchoring

- Give each hunter only the insights whose `target.coverage_ids` or `target.paths` intersect its own assignment, plus `scope: "run"` insights. Never the whole log. Cap the injected set at ten items; on overflow prefer `blocked_method` and `unit_shape` over `boundary_fact`.
- Send insights as **negative constraints and source facts to re-establish**, never as exemplars. "`requireScope` is applied in `middleware/authz.ts` for every route registered in `routes/index.ts` — establish this yourself before relying on it" is allowed. A candidate's title, trace, payload, or severity is not. This is what keeps anti-pattern 8 intact: nothing carried may work as a worked example of what to find.
- Send `rejection_reason` insights only in generalized form, never naming an accepted finding.
- An insight is a hypothesis, never evidence. A hunter that relies on one still records its own `reviewed_paths` and checks. An insight alone can never close a unit.
- Before a new wave, drop insights whose target units are all terminal, and mark an insight `superseded` when a later wave contradicts it.

### The independence boundary is absolute

**Verifiers receive no reflection-log content.** Phase 3 candidate verifiers and Phase 5 record verifiers see only the candidate record, the source, and their own prompt — exactly as in the unmerged workflow. Reflection flows parent → hunters only.

The coverage critic's input set is the closed list in `HUNTING.md` and is not widened here. Where a `unit_shape` or `missing_result` insight matters to coverage, the parent acts on it directly — by re-shaping the unit or re-assigning it — rather than by adding the insight to the critic's prompt.

## Part C — Run-local knowledge base (optional)

For large runs, the parent may index its own artifacts so hunter prompts can be filled from one place. This is a convenience over audit-owned notes; it is not a second source of truth.

`<output-dir>/kb/chunks.jsonl` — one JSON object per line, preceded by a provenance header line `{"_provenance": true, "source_ref": "<commit>", "dirty": false, "built_at": "<iso8601>", "wave": <n>}`. Chunk sources are `architecture.md` sections, `threat-model.md` sections, `entities/*.md`, `history-leads.json`, `reflection-log.json`, and ledger unit descriptors.

```json
{"id": "insight:rl-0031", "source_file": "reflection-log.json", "entity_type": "entity|threat_model|history_lead|insight|unit", "coverage_ids": ["..."], "start_line": null, "end_line": null, "chunk_text": "..."}
```

Never index target source content, and never index a secret value.

Agents do not read the file. The parent queries it with a deterministic local helper (already-installed `node` or `python3`, no network, no install) that scores BM25 or TF-IDF over lowercased alphanumeric tokens with optional `entity_type` and `coverage_ids` filters, default top-5, and pastes only the relevant subset into a hunter's prompt. A missing or empty file returns nothing and falls back to reading the artifacts directly; it never errors and never counts as coverage. Warn when the header's `source_ref` differs from `run-metadata.json`.

The knowledge base is run-local. Cross-run carry-forward stays governed solely by the prior-run rules in `SKILL.md`.

## Anti-patterns specific to this file

1. Reporting a historical commit as a finding, or treating a diff as present-source evidence.
2. Reproducing, masking, or hashing any part of a credential found in history.
3. Claiming a clean history under `partial_shallow` or `unsupported_vcs`.
4. Running any Git command that writes to the target's working tree, index, or object store.
5. Sending reflection content to a verifier, or sending a prior candidate's trace to a hunter as an exemplar.
6. Spending a reserved critic or verifier call on reflection.
7. Letting a knowledge-base miss stand in for coverage.
