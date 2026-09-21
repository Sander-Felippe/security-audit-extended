# security-audit-extended

A source-first, read-only security audit skill for coding agents. It merges Cloudflare's audit workflow with methodology from Google's Mantis skill suite.

**This is an unofficial personal merge.** It is not released, maintained, or endorsed by Cloudflare or Google.

## Who made what

| | |
| --- | --- |
| **Cloudflare** — the base | The structure and every rule that makes it trustworthy: the six phases, the coverage ledger, the verdict contract, the write isolation, the validators. Eighteen of their twenty files ship here **byte-identical to upstream**. MIT. |
| **Google (Mantis)** — the methodology | The ideas behind the five companion files. **No Mantis code, prompt text, or file is copied into this repository.** Their skills were read, and the methodology was re-expressed in Cloudflare's vocabulary and bounded by Cloudflare's rules. Apache 2.0, included for attribution. |
| **This repository** — the merge | Two additive edits to Cloudflare's `SKILL.md` and `VALIDATION-AND-REPORTING.md`, the five companion files, `validate-companion-artifacts.cjs` and its tests, `ORIGIN.md`, and this README. MIT. |

[ORIGIN.md](ORIGIN.md) has the file-by-file account, the exact upstream revisions, and the twelve Mantis behaviours that were deliberately dropped with the reason for each.

## What it is

Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) provides the structure: six phases, a deterministic coverage ledger, stable fingerprints, a three-verdict contract (`confirmed` / `needs_validation` / `rejected`), write isolation between the coordinating agent and its hunters and verifiers, and two dependency-free validators that make the output machine-checkable.

Google's [Mantis](https://github.com/google/mantis) contributes methodology that Cloudflare's workflow does not have: threat modelling, structural indexing, history mining, a graded reproduction ladder, severity calibration against inflation, deduplication, and exploit chaining.

The merge keeps Cloudflare's structure intact and re-expresses Mantis's methodology inside it, bounded by Cloudflare's rules.

## What it adds to the Cloudflare workflow

| Companion | Read in | What it adds |
| --- | --- | --- |
| `THREAT-MODEL-AND-INDEX.md` | Phase 1 | Named threat model with actor × boundary pairs, entity records, optional structural index, dependency-aware fan-out |
| `HISTORY-AND-REFLECTION.md` | Phase 1 and between waves | Leads mined from the target's own Git history; parent-side reflection between hunter waves |
| `REPRODUCTION-LADDER.md` | Phases 2 and 3 | Graded local evidence R0–R3a and what each rung may claim |
| `CALIBRATION.md` | Phase 5b | A named, auditable catalogue of severity caps |
| `DEDUPE-AND-CHAINS.md` | Phases 3 and 5c | Root-cause identity predicate, merge rules, exploit-chain assembly |

Plus `validate-companion-artifacts.cjs`, a third validator for the artifacts these companions produce. It checks structure and, more usefully, cross-references: that a `confirmed` record actually reached R3, that calibration only lowered severity, that a chain's links are confirmed and its composite result exceeds the strongest link, and that every fingerprint and coverage ID referenced exists.

## Six invariants

1. **Read-only.** No patch step, no remediation loop, no re-attack pass. It describes the smallest effective source fix and stops.
2. **Additive only.** A threat model, index result, history lead, or correlation may broaden work and reorder priority. None of them closes a coverage unit, suppresses a candidate, or changes a verdict.
3. **No new record fields.** Every added artifact is a separate file; nothing touches `findings.json` or its schema.
4. **Calibration only lowers.** It never raises a severity and never assigns one to an unconfirmed record.
5. **Chains are not findings.** They never enter the finding count and never change a link's severity.
6. **R3 or `needs_validation`.** A `confirmed` record requires a bounded local result at the component's real interface.

## Install

Install the whole folder, not just `SKILL.md`.

**Claude Code**

```sh
git clone https://github.com/Sander-Felippe/security-audit-extended.git
cp -r security-audit-extended ~/.claude/skills/          # all projects
cp -r security-audit-extended .claude/skills/            # one project only
```

**Codex, via the Skills CLI**

```sh
npx skills add ./security-audit-extended --skill security-audit-extended --agent codex --global
```

Restart the agent afterwards if the skill does not appear.

Cloudflare's original skill can stay installed alongside this one; the skill names differ (`security-audit` upstream, `security-audit-extended` here).

## Use

Ask for a focused review, and the skill answers from the relevant parts without writing files:

> Is this handler's tenant check sufficient?

Ask for an audit, and it runs the complete six-phase workflow and writes its artifacts:

> Run a full security audit of this repository.

The default profile is `standard`. Say `quick` for a bounded first pass, `deep` for a high-stakes target, or name paths to scope the run. A scoped or `quick` run reports itself as partial coverage.

## Before running a full audit

```sh
node --test validate-findings.test.cjs validate-coverage-ledger.test.cjs validate-companion-artifacts.test.cjs
```

All tests must pass; at the current revision there are 130 of them.

Three environment requirements, checked in this order:

1. **Delegated agents.** The workflow depends on isolated hunters and independent verifiers. Do not simulate them.
2. **Node.js with `O_NOFOLLOW` and `O_NONBLOCK`.** All three validators refuse to read without them. Node on native Windows does not expose these constants, so the validators cannot run there. This is inherited from Cloudflare's originals and is a deliberate refusal, not a defect to patch out. Use Linux, macOS, or WSL.
3. **An OS-enforced sandbox.** A working validator does not prove a sandbox exists. Without every control in `SKILL.md` "Universal execution safety", nothing executes.

## Known trade-off

Invariant 6 is stricter than Cloudflare's original, which allowed a verifier to confirm on source alone when it could not safely reproduce. The consequence is deliberate: **in an environment with no usable sandbox, this edition produces no `confirmed` records at all** — only `needs_validation` with the missing capability named. If that is the wrong trade for a given run, use the unmerged Cloudflare skill rather than relaxing the rung.

## Provenance

Eighteen of Cloudflare's twenty files are byte-identical to upstream. Only `SKILL.md` and `VALIDATION-AND-REPORTING.md` were modified, additively, and the phase numbering is unchanged so every cross-reference inside the untouched files still resolves. [ORIGIN.md](ORIGIN.md) records the exact revisions and how to re-apply the merge when upstream moves.

## Licences

- Cloudflare's files and the structure they define: MIT — see [LICENSE](LICENSE).
- Google's Mantis: Apache 2.0 — see [LICENSE-MANTIS](LICENSE-MANTIS). No Mantis code, prompt text, or file is copied here; the licence is included for attribution of the methodology this work derives from.
- The files original to this repository — the five companions, `validate-companion-artifacts.cjs` and its tests, `ORIGIN.md`, and this README: MIT, same terms as [LICENSE](LICENSE).

## Responsible use

AI models are non-deterministic and can produce findings that are wrong. Every finding this skill reports must be verified by a person before it is acted on or reported to anyone. Do not mass-file AI-generated reports to maintainers. A failed reproduction does not prove a finding is false, and a successful one does not prove it is exploitable everywhere.

This package contains no results from a real audit. It is instructions and validators.
