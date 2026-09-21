# Origin and Divergences

This is a personal merge of two upstream projects. It is not an official release of either, and neither Cloudflare nor Google endorses it.

## Sources

| | |
| --- | --- |
| **Structure and workflow** | [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), revision `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`, folder `skills/security-audit`. MIT. |
| **Added methodology** | [google/mantis](https://github.com/google/mantis), revision `6f523a3` (`Add campaign planner, replanning and steering`). Apache 2.0. Methodology only; no Mantis code, prompt text, or file is copied here. |
| **Prepared** | 2026-09-21 |

Both licences are preserved verbatim: [LICENSE](LICENSE) (Cloudflare, MIT) and [LICENSE-MANTIS](LICENSE-MANTIS) (Google, Apache 2.0). The Cloudflare structure, phase numbering, verdict contract, coverage ledger, schema, and validators are the base; Mantis contributes methodology that has been re-expressed in Cloudflare's vocabulary and constrained by Cloudflare's rules.

## Files

**Unchanged from Cloudflare** — byte-identical to revision `c1c8a8c`:

`RECONNAISSANCE.md`, `HUNTING.md`, `ATTACK-CLASSES.md`, `AI-AND-LLM.md`, `CLIENT-SIDE.md`, `CLOUD-AND-DEPLOYMENT.md`, `DATA-ISOLATION-AND-LIFECYCLE.md`, `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `MEMORY-SAFETY-AND-BINARY.md`, `PROTOCOLS-RPC-AND-MESSAGING.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`, `WEB-PROTOCOL-AND-AUTH.md`, `report-schema.json`, `validate-findings.cjs`, `validate-findings.test.cjs`, `validate-coverage-ledger.cjs`, `validate-coverage-ledger.test.cjs`.

**Modified** — two files, additively:

- `SKILL.md` — new `name` and `description`; a merged-edition table and six governing invariants; the new parent-owned artifacts added to the write-isolation list; the new `run-metadata.json` fields; the six phases annotated with where each companion is read; the third validator added to the completion condition; anti-patterns 11 through 18.
- `VALIDATION-AND-REPORTING.md` — two edits. The Phase 5 completion sentence now separates `verification_status` from `run_status`, because this edition has work after Phase 5a. The `REPORT.md` section gains item 8 for the exploit-chains section and the run limitations this edition tracks.

Nothing was removed from either file. Phase numbering is unchanged, so every cross-reference inside the untouched Cloudflare files still resolves.

**New**:

- `THREAT-MODEL-AND-INDEX.md` — threat model as a named artifact, entity records, the optional structural index, dependency-aware fan-out, deterministic adversarial sweep and open look.
- `HISTORY-AND-REFLECTION.md` — leads mined from the target's own Git history; parent-side reflection between hunter waves; an optional run-local knowledge base.
- `REPRODUCTION-LADDER.md` — rungs R0 through R3a, the reached-sink evidence gate, capability checks, environment tiers, and the rules that keep a reproducer from becoming a weapon.
- `CALIBRATION.md` — the named severity-cap catalogue with a fixed precedence, the attacker-position barrier test, the absolute gates, and stale-evidence suppression.
- `DEDUPE-AND-CHAINS.md` — the root-cause identity predicate with merge rules, and exploit-chain assembly.
- `validate-companion-artifacts.cjs` and `validate-companion-artifacts.test.cjs` — a third validator for this edition's artifacts and their cross-references.
- `ORIGIN.md` — this file.

## What was taken from Mantis, and in what shape

| Mantis capability | Here |
| --- | --- |
| Threat model generation | `threat-model.md` with actor × boundary pairs seeding ledger units; the production-signal checklist as a calibration input only |
| Structural / semantic index | Optional, hint-only, sandboxed, with a precision ladder and mandatory grep union |
| Directory rollup summaries | Optional, written under the output directory, never into the target |
| Entity knowledge base | `entities/*.md` with a mandatory drift check against current source |
| Hypothesis planning, dependency fan-out | Two-hop fan-out floor plus index callers; union only, never narrowing |
| Adversarial sweep, random digging | Kept, but seeded deterministically from `run_id` and the sorted coverage IDs, and recorded |
| History mining | `history-leads.json`, local `git` only, with the removed-guard case and strict secret handling |
| Reflection between rounds | `reflection-log.json`, parent-side, zero budget, hunters only — never verifiers |
| Deduplication | Identity predicate, merge rules, and the calibration cases; embedding-based tiers dropped |
| Vulnerability chaining | `chains.json`, parent-owned, never a finding, never inheriting reproduction |
| Severity calibration | The cap catalogue and gates, expressed through the existing enum fields with no numeric score |
| Critic's viability refutations | Mapped onto the existing `rejected` verdict with a drift fail-safe |
| Reproduction ladder | R0–R3a; the staging and cloud rungs dropped |

## What was deliberately dropped from Mantis, and why

1. **Patching and the adversarial patch-verification loop.** This audit never writes to the target. Mantis proposes a fix, applies it, and re-attacks to grade it. That is a different product with a different risk profile, and it breaks the read-only guarantee that makes this workflow safe to point at someone else's repository. The audit describes the smallest effective source fix and stops.
2. **The re-attack variant ladder.** Boundary-mutated payload families, encoding variants, alternate endpoints, and role variants exist to grade a patch. Without a patch step they only multiply exploit-shaped material.
3. **Staging, pre-production, and cloud-VM execution tiers.** They probe deployed or shared infrastructure, need external network to provision, and spend paid quota. Everything they could settle becomes a `needs_validation` blocker with an owner-observed plan.
4. **The `statically_confirmed` verdict.** It lets a static claim wear a reproduction label. Here a static claim is `needs_validation` with its blocker named.
5. **Global dismissal on a `SAMPLE_OR_TEST_ONLY` verdict.** In Mantis that verdict dismisses every finding in the pass. Here it lowers a ceiling and de-prioritizes; it never suppresses a demonstrated boundary violation.
6. **Embedding-based deduplication.** It needs an external embedding provider, which the no-network rule forbids. The predicate stops at root-cause comparison and, when undecided, keeps both candidates.
7. **Numeric risk scoring.** `(impact + likelihood) × multiplier` lets likelihood push the headline above demonstrated impact, which Cloudflare forbids. The caps survive; the arithmetic does not.
8. **`outrage_commentary` and reputational weighting.** No schema home, and it inflates priority past demonstrated impact.
9. **Low-severity records for hygiene and unreproduced candidates.** Mantis keeps them as `LOW`. Here, hygiene is `rejected` or a hardening note, and an unreproduced candidate is `needs_validation`. Cloudflare's anti-patterns 1 and 2 already settle this.
10. **The mutable cross-run knowledge base with per-pass archives, staleness banners, and snapshot sentinels.** Cloudflare runs are immutable per `run-<N>`, and `source_ref` plus the dirty-worktree flag already carry what the sentinel layer was for. The knowledge base here is run-local.
11. **Binary and firmware tooling directives, and the live-endpoint target mode.** Such tooling is allowed only when already installed locally and only inside the sandbox. The live-endpoint mode is gone entirely.
12. **Agents writing shared state.** In Mantis, stages write findings files and learning logs directly. Here the parent is the only writer of every shared file, per the existing write-isolation rules.

## Deliberate design decisions

- **Two files touched, not five.** Every new instruction lives in a companion file that `SKILL.md` points to. This keeps the diff against Cloudflare small enough to re-apply when upstream moves.
- **Phase numbering preserved.** New work is inserted as Phase 5a, 5b, and 5c rather than as new phases, so the phase references inside the untouched Cloudflare files still resolve.
- **A validator, not prose.** Every new JSON artifact has a machine contract. A new artifact specified only in prose would repeat the mistake this workflow exists to avoid: `validate-companion-artifacts.cjs` checks structure, enums, and — more usefully — cross-references. It enforces that a confirmed record reached R3, that calibration only lowered severity, that a chain's links are confirmed and its composite exceeds the strongest link, and that every fingerprint and coverage ID referenced actually exists.
- **Absent artifacts are reported, never failed.** A `quick` run that produced no chains and no history leads still validates what it did produce.
- **English throughout.** The base is Cloudflare's English text; a partial translation would split the vocabulary the validators and prompts depend on.

## Environment requirements

Before starting a full audit, check three things:

1. **Delegated agents.** The workflow depends on isolated hunters and independent verifiers. Do not simulate them. If the platform has no delegation mechanism, use guidance mode with explicit limits, or record an incomplete run.
2. **Node.js with `O_NOFOLLOW` and `O_NONBLOCK`.** All three validators refuse to read without them. Node on native Windows does not expose these constants, so the validators cannot run there — this is inherited from Cloudflare's originals and is a deliberate refusal, not a defect to patch out. Use Linux, macOS, or a properly configured WSL environment. Never remove the protection to make a validator run, and never substitute an informal check for validator approval.
3. **An OS-enforced sandbox.** A working validator does not prove a sandbox exists. Without every control in `SKILL.md` "Universal execution safety", nothing executes: candidates stay `needs_validation` with the missing capability named, and the run records itself incomplete rather than lowering the bar.

Run the test suites to check the environment:

```sh
node --test validate-findings.test.cjs validate-coverage-ledger.test.cjs validate-companion-artifacts.test.cjs
```

## Installation

Install the whole folder, not just `SKILL.md`.

- **Claude Code** — copy the folder to `~/.claude/skills/security-audit-extended/` for all projects, or `.claude/skills/security-audit-extended/` inside a project.
- **Codex, via the Skills CLI** — `npx skills add "<path>/security-audit-extended" --skill security-audit-extended --agent codex --global`. Drop `--global` and run from the project folder to install it locally.

The upstream Cloudflare skill can stay installed alongside this one; the skill names differ (`security-audit` upstream, `security-audit-extended` here).

## Keeping up with upstream

To adopt a later Cloudflare revision, diff the new revision against `c1c8a8c` and re-apply the two edits listed above by hand. Do not replace this folder with a fresh download of either upstream — that discards the merge. Line endings here are LF; normalize before diffing if your tooling rewrites them, or every file will appear changed.

This package contains no results from a real audit. It is a set of instructions and validators; it has not been used to find a vulnerability in any specific codebase, and installing it is not the same as running the workflow successfully.
