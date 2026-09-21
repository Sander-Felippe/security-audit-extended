# Remediation Handoff to OpenSpec

Read this only when the user explicitly asks for a remediation proposal, and only after a completed audit. It is not part of the six phases, it is never run automatically, and it never executes.

[OpenSpec](https://openspec.dev) is a spec-driven change framework: `explore`, `propose`, `apply`, `archive`. This file defines how a finished audit hands its confirmed records to it without weakening anything the audit established.

## The boundary

**The audit ends before the proposal begins.** This file describes how to write the proposal, not how to apply it.

- The agent that audited must not apply the fixes. The audit's whole verification discipline exists because the agent that found a defect is not trusted to confirm it. The same holds for the patch: whoever writes it does not get to declare the invariant satisfied. Run `apply` in a separate session, preferably with a different agent.
- Writing a proposal does not modify the target. Producing `proposal.md`, `specs/`, `design.md`, and `tasks.md` is writing documents into the OpenSpec change folder. The audit's read-only invariant still holds for the repository under review until the user runs `apply` themselves.
- If no audit artifacts exist, do not invent them. Say the audit has to run first.

## What is eligible

| Record | Becomes |
| --- | --- |
| `confirmed` | A requirement in `specs/` and one or more tasks in `tasks.md`. |
| `needs_validation` | An item for `explore`, or a question for the system's owner. **Never a task.** Its blocker is an unresolved fact; a fix for it is a change with all the cost and risk and none of the established benefit. |
| `rejected` | Nothing. Mention it only if it explains why an obvious-looking change is absent. |
| A chain in `chains.json` with verdict `confirmed` | Not its own requirement. Its `break_points` reorder the tasks of the links it names. |
| A hardening note | At most a separate, clearly labelled change. Never mixed into a change that fixes a confirmed finding. |

Read `findings.json`, `coverage-ledger.json`, and `chains.json` from the run's output directory. Read the final records, never the hunter write-ups.

## Decomposing into changes

One OpenSpec change per **invariant**, not per finding.

- Group several findings into one change only when a single source change at one decision point enforces all their invariants. Say so explicitly in `proposal.md`, and list every fingerprint the change closes.
- Split one finding into several changes when its invariant has to be enforced at genuinely separate decision points. Each change carries the same fingerprint and states which part of the finding it closes.
- **Let `chains.json` drive grouping before severity does.** A chain's `break_points` name the link whose fix collapses the chain. Fixing that link first is often cheaper than fixing every link, and a proposal built finding-by-finding will miss it. When a break point exists, the change that fixes it comes first and says which chain it breaks.

Name the change after the invariant, not the vulnerability class: `enforce-tenant-scope-on-export`, not `fix-idor`.

## Mapping a record to the artifacts

### `proposal.md`

- **Why**: the demonstrated result, in the audit's own words — the lower-trust principal, the crossed boundary, the affected principal or resource, and the observed outcome. Copy from the record; do not restate it more dramatically.
- **Fingerprints closed**: every one, verbatim.
- **Severity**: copy `severity.overall_severity` for each fingerprint, verbatim. Do not recompute, aggregate, or average it. If several findings of different severities share the change, list each one's severity separately.
- **Scope**: what this change does not cover, including any `needs_validation` record touching the same code.
- **Source ref**: the reviewed commit the audit ran against. If the worktree has moved since, say so — the cited lines may have drifted.

### `specs/`

The requirement **is** the audit's invariant. Each confirmed record already states the invariant the code must enforce; write it in OpenSpec's requirement form rather than inventing a new one.

Use the delta heading OpenSpec's own instructions specify for the change type. The requirement and scenario format:

```markdown
## ADDED Requirements

### Requirement: Export scope
The export handler SHALL resolve the tenant from the authenticated
identity and SHALL reject any tenant identifier supplied by the caller.

#### Scenario: Caller exports their own tenant
- **WHEN** an authenticated caller requests an export with no tenant parameter
- **THEN** the handler returns only records belonging to the caller's tenant

#### Scenario: Caller supplies another tenant's identifier
- **WHEN** an authenticated caller requests an export with a tenant
  identifier they do not own
- **THEN** the handler rejects the request and returns no records
```

Every requirement carries at least two scenarios: **one allowed case and one rejected case**. The rejected case comes from the finding's own reproduction — the bounded local input that produced the boundary violation, restated as behaviour that must not occur. Do not include the exploit payload; state the condition, not the weapon.

The regression case in `FINDINGS-DETAIL.md` is the source for these scenarios. If a finding has no regression case, the record is incomplete; go back to the audit rather than inventing one.

### `design.md`

Constrained, not open. The audit already identified the narrowest change that enforces the invariant at the last trusted decision point. `design.md` records that decision and the alternatives the audit rejected — it is not a fresh design exercise.

State explicitly what new surface the change introduces. A fix is a change, and changes can be wrong in their own way.

### `tasks.md`

- Each task carries the fingerprint it serves.
- **Task order is implementation order, never a severity ranking.** Order by dependency, regression risk, and deploy window. Say this in one line at the top of the file, or someone will read the ordering as a gravity ranking and the audit's calibration becomes noise.
- Every fix task has a paired regression-test task. A fix with no test that fails before it and passes after it is not finished.
- No task may be created from a `needs_validation` record.

## Secrets

Nothing in any OpenSpec artifact contains a credential value, in whole or in part, hashed or masked. This carries over from the audit unchanged: record the location and the variable name, and write `[SECRET REMOVED]` in place of the value. A rotation task names what must be rotated and where; it never quotes the secret.

## Closing the loop

`openspec verify` checks that the implementation matches the spec. **That is not the audit's verification and does not prove the boundary violation is gone.** Two different things share the word.

A finding is closed when, and only when:

1. The regression test fails against the pre-fix source and passes against the fixed source.
2. The finding's own reproduction — the R3 check recorded in `reproduction-ladder.json` — is re-run against the fixed source, inside the same sandbox controls, and the minimum boundary result no longer occurs.
3. Whoever performs step 2 did not write the fix.

Record the result. If the sandbox is unavailable for step 2, the finding is not closed: it is fixed-pending-verification, and the proposal says so. Never let `archive` stand in for that check.

A re-run of the full audit against the fixed source is the stronger closure, because a fix can move a defect rather than remove it, and because the change itself is new attack surface the audit has never seen.

## Anti-patterns

1. Auditing and applying the fixes in the same session, or with the same agent.
2. Turning a `needs_validation` record into a task.
3. Recomputing, aggregating, or re-wording a severity on its way into the proposal.
4. Reading task order as a severity ranking, or writing one that invites that reading.
5. Building the proposal finding-by-finding when `chains.json` names a break point.
6. Treating `openspec verify` or `archive` as evidence that a vulnerability is closed.
7. Putting an exploit payload, or any part of a credential, into a scenario.
8. Widening the fix beyond the narrowest change at the last trusted decision point because the change folder made it convenient.
9. Writing a proposal from hunter write-ups rather than the final validated records.
