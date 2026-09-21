# Threat Model, Structural Index, and Hypothesis Planning

Read this in Phase 1 of a full audit, after the baseline reconnaissance agents defined in [RECONNAISSANCE.md](RECONNAISSANCE.md) return and before seeding the coverage ledger. In guidance mode, use only the section asked about and create no files.

This file adds three parent-owned inputs to reconnaissance: a named threat model, an optional structural index of the source, and a hypothesis-planning discipline that turns both into ledger units. None of them decides a verdict.

## The additive-only invariant

Everything in this file may **broaden** work and **reorder** priority. Nothing in it may narrow, close, suppress, or excuse coverage.

- A threat model, an index result, a summary, or an entity record never closes a ledger unit. Only a hunter's structured result closes a unit, exactly as in [RECONNAISSANCE.md](RECONNAISSANCE.md).
- An index may add `starting_paths` to a unit and propose new units. It may never remove a unit, shrink `starting_paths`, or mark a unit `not_applicable`. Only a source fact marks a unit `not_applicable`.
- Absence of an indexed caller is not absence of a caller. Grep over the in-scope tree remains the exhaustive floor; the index decides **order of investigation, never membership**. Audit the union of the grep result and the index result.
- No artifact in this file adds a field to `findings.json`. `report-schema.json` is `additionalProperties: false` at every level; an `availability_tier`, `threat_actor`, or `symbol_id` key inside a record fails validation.

## 1. Threat model — `<output-dir>/threat-model.md`

The parent is the only writer. Derive it from the reconnaissance agents' returned facts plus its own reading; do not carry any assertion from a prior run that has not been re-derived from current source this run.

Write these sections in this order:

1. **System overview** — what the target is and what it is for, in five sentences or fewer.
2. **Deployment intent** — the verdict from the production-signal checklist below, with the checklist's answers.
3. **Trust boundaries** — each boundary named by the source control that defines it, with repository-relative `file` and symbol (`src/authz.ts#requireOwner`). A boundary with no identifiable enforcement point is recorded as *claimed, unenforced* and becomes a hunting priority, not a finding.
4. **Threat actors and reachable boundaries** — one named profile per actor, each listing exactly which boundaries from section 3 it can reach and what it wants. Use concrete profiles: `unauthenticated-network`, `authenticated-tenant-user`, `other-tenant-user`, `local-unprivileged-user`, `malicious-dependency`, `ci-job`, `operator`. Add or drop profiles to fit the target; do not use a profile the source gives no path for.
5. **High-value assets** — data, execution privilege, and availability targets, each with an availability tier: `critical` (continuous operation; downtime is immediate operational loss), `standard` (important, short downtime tolerable), `low` (non-blocking utility).

Keep the file under 1,200 words. Depth belongs in entity records, not here.

### Production-signal checklist

Answer all five before writing the deployment intent. Write `intent: sample-or-test-only` only when **every** answer is yes:

1. No asset in section 5 carries the `critical` or `standard` availability tier.
2. The source names no externally reachable service, daemon, server, or API, **and** carries no deployment descriptor (systemd unit, Dockerfile, Kubernetes or Helm manifest, load-balancer config, IaC, CI publish step).
3. There is no installable or publishable package and no runtime entrypoint (`console_scripts`, `entry_points`, `main()`, service binary, package manifest).
4. Every path in scope lies under `test`, `tests`, `example`, `examples`, `sample`, `samples`, `tutorial`, `demo`, `docs`, or `fixtures`, and none lies under `src`, `lib`, `pkg`, `internal`, `cmd`, `app`, `server`, or `core`.
5. No component takes a real, non-mock untrusted input into privileged logic.

Any answer of no, or any answer you cannot establish, yields `intent: production`. Re-derive this every run; never inherit it from a prior run's metadata.

**The verdict is a calibration and prioritization input only.** It lowers the severity ceiling and de-prioritizes units. It never converts a `confirmed` record to `rejected`, never suppresses a candidate, and never gates hunting. A demonstrated boundary violation in a file that the checklist called test-only is still a demonstrated boundary violation; see [CALIBRATION.md](CALIBRATION.md) for how it lands in severity.

### Feeding the ledger

Sections 3 and 4 drive unit seeding, but **not one unit per actor**. Unit identity stays what `RECONNAISSANCE.md` defines — surface × boundary × subsystem × attack class — and duplicate canonical IDs are a hard ledger error. Two actors reaching the same boundary are one unit.

- Seed one `planned` unit per canonical tuple that any actor can reach, and give the unit a parent bookkeeping field `threat_actors` listing every actor that reaches it. The list is excluded from `coverage_id`.
- `canonical_refs.boundary` stays the **source control that defines the boundary**, never an actor label and never a threat-model heading. Actor names are display text and are not stable across runs.
- Where two actors reach one boundary through genuinely different surfaces, that is already two different tuples and therefore two units. Never split a unit to give an actor its own copy.
- Record the availability tier and the deployment intent in `run-metadata.json` and, where relevant, as unit bookkeeping. They must not enter `coverage_id`, must not create or suppress a unit, and must not change a verdict.

## 2. Entity records and dependency map

`<output-dir>/entities/<component>.md`, parent-owned, one file per component the architecture summary names. Each entity states:

- the component's job in two sentences;
- every boundary control it claims to enforce, with `file:line` and the symbol;
- its availability tier;
- the attack classes historically or structurally relevant to it, with the companion file that covers each.

This is what makes a unit's `canonical_refs.boundary` reviewable rather than asserted.

**Drift check, mandatory before the ledger is seeded:** spot-check every entity assertion against current source. If an entity claims a variable is unsanitized and current code sanitizes it, correct or delete the assertion. Never carry an architecture or entity assertion that has not been re-derived from current source this run.

`<output-dir>/dependencies.json` — a JSON object whose keys are repository-relative source paths and whose values are arrays of the repository-relative paths that import or depend on the key. Write `{}` when no import structure is parseable. It exists to drive fan-out (section 4); it is never evidence.

`<output-dir>/summaries/<repo-relative-dir>.md` — optional bottom-up rollups for large targets. Summarize leaves first; when summarizing a directory, pass the model that directory's own files plus **only its child directories' summaries**, never the children's raw source. Each summary covers: core components; what the directory exposes to other modules; trust boundaries and external inputs it handles; sensitive operations (parsers, crypto, memory management, deserialization); and repository-local history of fixes in this area. Skip `node_modules`, `vendor`, `.git`, and build output for summarization — but keep them as ledger surfaces where the audit's scope includes dependency and CI review.

**Never write any of these into the target.** They live under `<output-dir>` only.

## 3. Structural index — optional, hint-only

Build `<output-dir>/structural-index/` before hunting when, and only when, all of the following hold: the required indexer is already installed locally, no dependency needs installing, nothing needs fetching, and the full sandbox control list in `SKILL.md` "Universal execution safety" can be enforced. Parsing target bytes is running code over target-controlled input: the build runs in an agent's sandbox, writes only to that agent's `scratch/`, and its outputs reach `artifacts/` only through the parent-side promotion procedure with explicit per-file and cumulative byte limits.

**The index is never required and never fails.** No tools, a parse failure, an unenforceable control, or a promotion rejection all yield an empty index, a recorded capability blocker, and grep-only behavior identical to the unmerged workflow.

### Backend precision ladder

Select per partition, not once globally. Highest available wins, and every result carries its `precision` and `backend`:

| `precision` | `backend` | Trust |
| --- | --- | --- |
| `semantic` | SCIP, LSIF, Kythe, clangd static index, snapshot-matched | Call absence is meaningful only here |
| `typecheck` | compiler or typechecker, `compile_commands.json` | Strong, still not exhaustive |
| `ast` | tree-sitter, ast-grep, language parser | Structural only |
| `symbol-only` | ctags plus regex call sites inside known function boundaries | Ordering hint |
| `heuristic` | regex | Ordering hint |
| `coverage-only` | grep; index empty | No index |

A language server is not equivalent to SCIP. Accept LSP output as `semantic` only with demonstrated snapshot identity and complete workspace coverage.

### Records

Symbols: `symbol_id`, `name`, `qualified_name`, `namespace`, `language`, `file_path`, `start_line`, `end_line`, `kind`, `signature`, `backend`, `precision`.
Call edges: `caller_id`, `callee_id`, `callee_name`, `file_path`, `line`, `edge_kind`.
Coverage rows: `file_path`, `indexed`, `backend`, `precision`, `unit_cache_key`, `status`.

`edge_kind` is one of `direct`, `indirect`, `virtual`, `macro`, `unresolved`, and the five are **never merged**. Indirect, virtual, macro, and unresolved edges are exactly the ones a security audit must not treat as absent.

Symbol identity: `scip:{symbol}`, `kythe:{uri}`, or `clangd:{usr}` natively; otherwise `fallback:{language}:{file_path}:{sha256(qualified_name|start_line|signature)[:16]}`. A `fallback:` id hashes a line number, so it changes on unrelated edits — never use it as a `canonical_refs` value. When a unit's surface is a symbol rather than a route, set `canonical_refs.surface` to the repository-relative path plus the symbol's `qualified_name`, **unencoded**: the existing `coverage_id` derivation in `RECONNAISSANCE.md` does the percent-encoding, and a pre-encoded ref would be double-encoded and would not match the same surface recorded conventionally elsewhere.

### Query contract

**The parent runs every query.** `structural-index/` is a parent-owned artifact and is never exposed to a sandbox or handed to a hunter. The parent queries it while preparing an assignment and pastes the resulting ranked list of call sites into the hunter's assignment block, alongside the `starting_paths` the unit already carries. The hunter prompt contract in `HUNTING.md` is unchanged: no new part, no index handle, no query tool in the hunter's hands.

Every query returns coverage alongside results: `partition_status` is `complete`, `partial`, `empty`, or `failed`.

- `resolve_symbol(name, language?, file?, namespace?)` → `{results, total, ambiguous, coverage}`. On `ambiguous: true`, never silently pick one — narrow by file or language, or plan for every match.
- `find_callers(symbol_id, limit, offset)` and `find_callees(...)` → `{results, total, has_more, coverage}`.
- `get_function_boundary(file, line)` → `{symbol_id, start_line, end_line, signature, precision, backend}`.
- `get_coverage(file?)` → `{total_files, indexed_files, failed, deferred, partition_status, backends_used}`.

Read "no callers" as "no **indexed** callers" unless `partition_status` is `complete` **and** `precision` is `semantic` **and** the index is snapshot-matched. In every other case the grep fallback is mandatory, and a partition below `complete` is a recorded limit, never coverage.

### Determinism

Never truncate in discovery order. Index in this priority: explicit target files and symbols from the plan; changed units and their known reverse dependencies; the containing packages and direct imports of those; then everything remaining in normalized path order. Bound with `max_units` and `max_source_bytes`, persist deferred units, and record `status` per partition.

Cache key per unit: `sha256(schema_version + extractor_name@version + language + compile_context_digest + ordered_input_content_digests + dependency_or_interface_digest)`. The snapshot id is deliberately **not** in the key; it is provenance, so identical units reuse across commits. Unit granularity: compilation unit for C/C++, package for Go, crate for Rust, compiler batch for Java/Kotlin, project for TypeScript, and otherwise one unit per source file, never bundled.

Write `manifest.json` last, by atomic rename. Record the manifest's `status`, per-language `precision`, and coverage counts in `run-metadata.json`, so a re-run on a degraded backend is visibly different rather than silently narrower.

## 4. Hypothesis planning

### Dependency-aware fan-out

For a scoped run over a diff, and for any changed-file set, expand before assigning:

1. From `dependencies.json`, take every file that imports each changed file directly or transitively **up to two hops**. This floor is mandatory.
2. Add symbol-level callers from the index (`resolve_symbol` → `find_callers`) on top.
3. Seed units for the **union**. The changed files themselves are always investigated.

Fan-out may only add investigations. Never use dependency narrowing to drop one. If the dependency map is incomplete or stale, treat all in-scope files as affected. Use the same two-hop radius when invalidating entity records, so a grandchild entity is not carried forward stale.

### Per-unit hypothesis

Give each unit a free-text `question` as a parent bookkeeping field: one specific tracing prompt derived from the threat model or a history lead ("trace the tenant id from `POST /api/exports` to the query in `reports/query.ts`; establish which layer, if any, scopes it"), not a generic class prompt. It must not enter `coverage_id`. The existing `starting_paths`, `ordinary_attack_class_block`, `selected_companion_blocks`, and `excluded_blocks` still carry the context.

### Two-wave reading inside one assignment

Instruct hunters to triage before deepening: grep the in-scope tree for the symbol to build the exhaustive candidate call-site set, use the index only to **rank** which sites to read first (it distinguishes real calls from comments, strings, and same-named variables), then audit the union. Open a site at its enclosing function via `get_function_boundary`, expanding to callers, callees, and whole file only as needed.

### Adversarial sweep and open look

In `standard` and `deep` profiles, seed one extra unit per wave from each of these, to counteract threat-model tunnel vision:

- **Adversarial sweep** — a component the threat model marks safe, low-risk, or out of interest, with the hunter explicitly instructed to ignore the threat model's safety assumptions and establish them itself.
- **Open look** — a unit over a file or directory whose `question` bookkeeping field is deliberately generic ("read this for anything that lets a lower-trust principal reach something it should not"), so the hunter is not steered toward a hypothesis. It is an ordinary unit with the full nine-part hunter prompt that `HUNTING.md` mandates; only the hypothesis is open, never the prompt contract.

Select both deterministically: seed the choice from `run_id` plus the sorted list of `coverage_id` values, and record the seed and the selected units in `run-metadata.json`. These are ordinary ledger units with the applicable ordinary attack-class block; they carry no special status. A random draw would make the ledger irreproducible and is not permitted.

### Cost

Two additions in this file spend budget and are subject to the strict budget gate in `SKILL.md`:

- **The structural index build is an agent invocation.** Count it before reconnaissance. If reserving it would leave the mandatory critic and validation reserves short, do not build the index: record the gap and hunt on grep.
- **The adversarial sweep and open look are hunter assignments.** They are assigned last in a wave and are the first units deferred when the hunting allowance runs out, with the existing reason `budget_cannot_reserve_critics_and_validation`. Never let them consume a reserve.

Everything else in this file is parent-side bookkeeping and costs nothing.

### Untrusted diff escalation

If the changed-file set cannot be trusted — no reliable diff, an unknown prior ref, or a dirty worktree whose extent is unclear — abandon diff-scoped planning and seed units across the whole in-scope tree, even when prior-run knowledge exists. A narrowed plan built on an untrusted diff silently drops newly added files.

### Relocated prior work

When a prior finding's anchor cannot be matched in current source, do not carry it forward and do not drop it. Seed a fresh unit whose `starting_paths` are the old path's directory subtree **plus** the results of a repository-wide search for the finding's primary symbol and title terms, so a moved or renamed defect is re-found. Keep the prior fingerprint. The existing prior-run rules in `SKILL.md` govern its state.

Line re-anchoring (`git blame --reverse`, or applying the diff hunk offset, then confirming the primary symbol appears within ±50 lines of the mapped line) is a **search hint only**. It may focus re-verification; it may never skip it, and it may never turn a revalidation unit into a carried record. On any failure, fall back to full re-discovery. Log the re-anchoring in run metadata, never in a findings record.

## Anti-patterns specific to this file

1. Letting a deployment-intent verdict suppress a demonstrated boundary violation.
2. Reading "no indexed callers" as "no callers", or marking a unit `not_applicable` on index evidence.
3. Using a `fallback:` symbol id, which embeds a line number, as a canonical reference.
4. Building an index by installing or fetching an indexer, or by parsing target bytes outside the sandbox.
5. Writing a summary, entity record, or index sidecar into the target tree.
6. Carrying a threat-model, entity, or architecture assertion from a prior run without re-deriving it.
7. Selecting an adversarial-sweep or open-look unit at random rather than from a recorded seed.
