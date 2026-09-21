# Deduplication and Exploit Chains

Read Part A in Phase 3, when consolidating candidates before validation. Read Part B in Phase 5c, after every retained record has passed independent verification and calibration. In guidance mode, use either part to answer the question asked and create no files.

## Part A — Deduplication

`SKILL.md` already requires a stable fingerprint per source-derived root cause, consolidation by fingerprint and root cause, and one final record per fingerprint. This part supplies the missing piece: the **predicate** for deciding whether two candidates share a root cause, and deterministic merge rules once they do.

### The bias

Over-reporting is recoverable; silent suppression is not. When the predicate cannot decide, keep both candidates distinct and let independent validation collapse them. Never merge on a hunch.

### The predicate

Two candidates share a root cause when **the defective decision point is the same code location** — the same missing, weak, or wrongly placed control. Everything else is a manifestation.

Work this order:

1. **Hard merge.** Merge only when the two candidates share an evidence or trace entry **line-inclusively** (the same `path:line`, not merely the same path) **and** describe the same defect. Two candidates at different lines of the same file are distinct until rule 2 or 3 says otherwise.
2. **Root-cause comparison.** On a miss at rule 1, synthesize five lines for each candidate and compare *those*, never the prose titles: component, vulnerability class, root-cause mechanism, failure condition, taint data flow. Identical on all five is a merge.
3. **Structural guard.** If the two candidates carry explicit and incompatible attack classes, do not merge, whatever else matches.
4. **Undecidable.** Keep both, note the considered-and-not-merged pair as parent bookkeeping on each linked ledger unit, and let Phase 3 verifiers resolve them. Never delete a candidate to resolve ambiguity.

### Calibration cases

These are the decisions the predicate has to reproduce:

- **Same defect, unrecognizably different wording → merge.** "Denial of service through a malformed cart payload header" at `controllers/cart_controller.py:18` and "unbounded memory consumption via unconstrained deserialization" at `services/cart/session.py:42` are one defect. Different file, different line, different vocabulary, one missing limit.
- **Caller and callee split across files → merge.** "Missing tenant boundary enforcement in API routing" at `api/gateway.py:115` and "IDOR via unauthenticated tenant header override" at `middleware/context.py:34` are two ends of one context-propagation flaw.
- **Same feature and directory, different mechanism → distinct.** A voucher-redemption race in `services/checkout/discount.py` and an arithmetic underflow in `services/checkout/pricing.py` are different defects. Proximity is not identity.
- **Same taint source, different sink and execution context → distinct.** Server-side template injection in `views/theme.py` and client-side DOM injection in `static/js/theme_customizer.js` have distinct sinks and distinct fixes.

The two cases that recur:

- **Same sink, different sources** — one root cause *if and only if* the same defective decision point admits both. Two independent sources reaching an otherwise-correct sink are distinct entry findings.
- **Same source, different sinks** — distinct, one record per sink, unless both sinks are reached through the same single missing control.

### Merge rules

Deterministic, mechanical, and parent-side. Never rewrite two records into a new prose summary.

- Keep the primary's fingerprint — the one whose evidence identifies the defective decision point most directly.
- Title: the more complete of the two.
- Severity is not set here. A candidate has no verdict yet, and only `confirmed` records receive severity. Calibration runs once, in Phase 5b, over the post-merge confirmed set.
- Trace and evidence: the union, de-duplicated, still ordered entrypoint → propagation → sink.
- Conditions: the union. A merged record's conditions must still be jointly satisfiable; if they are not, the merge was wrong — unmerge.
- Description, impact, and remediation: concatenated, not summarized away.
- **Refuse to merge two candidates established against different source refs.** Their locators may no longer describe the same code. Keep them separate and record the refusal.

### Across runs

A prior record matches a current candidate only when their source refs are the same and the predicate above holds. When the refs differ, treat the pair as *not matched*: keep the current candidate active and record it as a possible match to the prior record. Never suppress on a cross-ref guess.

**Regression override.** When the prior match was resolved — fixed, rejected, or ruled non-viable — and the pair is not matched, keep the current candidate fully active and flag it as a possible regression against the prior record. This outranks every other suppression rule. The prior-run rules in `SKILL.md` otherwise govern.

### Recording

Merges are already visible in the ledger: every linked unit records the decision, and `findings.json` keeps one record per fingerprint. Record a non-merge that a naive reading would have merged as parent bookkeeping on the linked units, so the next run does not re-litigate it. If both candidates survive to `confirmed` and share a symbol or file, the fact is also visible as an ordinary `correlations` entry in `chains.json` — an observation, never a merge decision.

## Part B — Exploit chains

A chain is a statement that two or more confirmed defects compose into a result none of them produces alone. Chains are reported so owners fix the cheapest link first. **A chain is never a finding.**

### Eligibility

- Every link is a `confirmed` record in the final `findings.json`. A `needs_validation` record may never be a link: its unresolved blocker is exactly the step the chain needs proven.
- Every link is established against the **same** source ref as the run. Links across refs are ineligible — their locators and their pre- and post-conditions may no longer hold together.
- Fewer than two eligible links means no chain. Write `chains.json` with an empty `chains` array and state the reason in the report's limitations; this is not an error, and there is no field inside `chains.json` for it.

### Composition predicate

For an ordered pair (A, B): **does A's demonstrated post-condition satisfy a precondition of B that the attacker could not otherwise satisfy?**

If B's precondition is already reachable without A, there is no chain — B alone is the finding. Compare declared pre- and post-conditions from the records' `conditions` and `execution.observed_result`. Never compare titles or descriptions: those are prose, and prose similarity is not composition.

### A valid chain requires all three

1. **Entry** — the first link is reachable by a genuine lower-trust principal.
2. **Pivot** — for each adjacent pair, a named capability A yields and B consumes, stated as a concrete state change, not a possibility.
3. **Terminal effect** — a combined result **strictly greater** than any single link's. If the composite equals the strongest link, emit no chain.

### Inherited properties

- `entry_principal`, and the privilege the chain requires, come from the **entry link only**. An unauthenticated entry escalating to administrator is an unauthenticated chain, not an administrator one.
- User interaction is required if **any** step requires it.
- The chain's evidence standard is the **weakest** link's. A chain is at most source- and sandbox-established; reproducing each link does not prove the end-to-end composition, and a chain may never claim end-to-end reproduction. Reaching a terminal effect is never attempted against anything deployed or shared.

### Anti-invention

- Correlate on **structural fields only** — symbols extracted from evidence paths, attack classes, repository-relative paths. Titles and descriptions are prior model output: quote them, never parse them for meaning.
- Correlation strength, strongest first: shared symbol > shared file > shared attack class. Emit a shared-attack-class correlation only *across* files.
- Drop generic symbols (`main`, `init`, `get`, `set`, `parse`, `handler`, `validate`, `data`, `result`, `run`, `new`) and anything that is only a numeric tail. A correlation group of one is never emitted.
- **A correlation is a reason to look, never evidence that a chain exists.** It never creates a record, never changes a severity, status, or confidence, and never merges anything. Establish reachability from source before claiming a chain.
- Settle chains deterministically, never by a single model verdict. Link states: `supported`, `open`, `refuted`. Chain states: `confirmed` when every link is `supported`; `refuted` when every link is `refuted`; `open` otherwise. Support requires positive evidence; refutation requires both an explicit disproof **and** no supporting evidence — a pivot nobody examined stays `open`. Err toward `open`.
- **Chain identity** is the ordered sequence of constituent fingerprints **plus** at least one line-inclusive evidence path per corresponding link. Sequence equality alone is not identity, because fingerprints do not carry line numbers.

### `<output-dir>/chains.json`

Parent-owned. Not validated by `report-schema.json`. `findings.json` and its schema are unchanged; links are by fingerprint string only, and no record is created or modified.

```json
{
  "run_id": "<from run-metadata.json>",
  "source_ref": "<the run's reviewed ref>",
  "chains": [
    {
      "chain_id": "chain-<16 hex, from the ordered link fingerprints>",
      "title": "Exploit chain: <terminal effect> via <A> then <B>",
      "verdict": "confirmed|open|refuted",
      "links": [
        {
          "order": 1,
          "fingerprint": "<fp-A>",
          "role": "entry",
          "provides": "<post-condition A demonstrably establishes>",
          "link_status": "supported|open|refuted"
        },
        {
          "order": 2,
          "fingerprint": "<fp-B>",
          "role": "pivot|terminal",
          "requires": "<precondition of B that A satisfies>",
          "unreachable_without_prior": true,
          "link_status": "supported|open|refuted"
        }
      ],
      "entry_principal": "<lower-trust principal of link 1>",
      "user_interaction": "required|none",
      "composite_result": "<terminal effect, source- or sandbox-established>",
      "composite_severity": "informational|low|medium|high|critical, or null",
      "blockers": ["<exact unestablished pivot, when verdict is open>"],
      "break_points": ["<the single link whose fix breaks the chain>"],
      "counts_as_finding": false
    }
  ],
  "correlations": [
    {
      "kind": "shared_symbol|shared_file|shared_attack_class",
      "key": "<symbol, repository-relative path, or attack class>",
      "members": ["<fp>", "<fp>"],
      "status": "observation_only"
    }
  ]
}
```

`composite_severity` is `null` unless `verdict` is `confirmed`, and when set it obeys [CALIBRATION.md](CALIBRATION.md) exactly as a record would — including the entry-privilege rule, which reads the entry link's principal, not the terminal link's.

### No double counting

1. `counts_as_finding` is always `false`. A chain never enters `findings.json`, never appears in the confirmed-findings count, and never changes a ledger count. The report's finding total is the number of records in `findings.json`, full stop.
2. Link records keep their own severity unchanged. A chain never annotates, raises, or lowers a link. Each link is still fixed on its own merits.
3. `composite_severity` belongs to the chain row alone. It is never summed with link severities and never exceeds the demonstrated composite result.
4. A record may appear in several chains and is still one finding. Report chains in their own section that names each chain's constituent fingerprints and states that those findings are already counted above.
5. No composite greater than the strongest link means no chain.
6. A fingerprint in a chain is never re-fingerprinted. `chain_id` lives in its own namespace and cannot collide with a finding fingerprint.

### Report placement

Chains go in a section of their own in `REPORT.md`, after the confirmed findings and before needs-validation. Each chain states its verdict, entry principal, ordered links by fingerprint and title, the composite result, and the break point. An `open` chain carries its blockers and no severity. A `refuted` chain is retained in `chains.json` so a later run does not re-propose it, and is not reported.

## Anti-patterns specific to this file

1. Merging two candidates at different lines of one file without establishing a shared defective decision point.
2. Merging on title similarity, or on an embedding score, rather than on root-cause comparison.
3. Suppressing a current candidate against a prior record established at a different source ref.
4. Building a chain out of a `needs_validation` link, or out of links from different source refs.
5. Emitting a chain whose composite result does not exceed its strongest link.
6. Counting a chain as a finding, or letting a chain change a link's severity.
7. Treating a correlation as evidence of composition.
8. Claiming end-to-end reproduction of a chain.
