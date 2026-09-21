# Severity Calibration

Read this in Phase 5b, after every record retained in `findings.json` has passed independent verification and before any prose is written. In guidance mode, use it to explain why a severity is what it is.

Calibration exists to stop severity inflation. It is a parent-side pass over `confirmed` records only, and it is **monotonically downward**: a calibration rule may lower a severity or leave it alone. It may never raise one, never assign severity to an unconfirmed record, and never change a verdict.

The anchors in `SKILL.md` "Separate priority from certainty" remain the definition of each level. This file adds a named, auditable catalogue of the reasons a record sits below the level it first felt like.

## The governing principle: marginal capability

Severity is bounded by the capability the attacker gains **over the position they already had**. If the demonstrated result grants no meaningful new control, access, or reach beyond the prerequisite position — or is obtainable by legitimate means available to that same principal — the record is capped or rejected, whatever the sink looks like.

This bound outranks every escalating consideration, including a security-control bypass.

## Order of operations

1. Confirm the record is `confirmed`. Anything else leaves this pass untouched: a `needs_validation` record has no severity, and its blocker is not a calibration input.
2. Establish `attacker_position` (section 1).
3. Set `severity.impact.score` from the demonstrated result and blast radius, and `severity.likelihood.score` from the demonstrated conditions. Apply the one escalation rule, `security_control_bypass`, **here** — it belongs to reading the anchor, not to capping it. Record the result as `pre_calibration_overall`.
4. Run the capping catalogue (section 2), recording every rule as `applies`, `does_not_apply`, or `unknown`. Never apply `security_control_bypass` in this step: doing so would push the post-calibration reading above `pre_calibration_overall`, which the validator rejects.
5. Apply the most restrictive cap that fired. `overall_severity` is the lower of the anchor reading and the cap, and can never exceed `impact.score`.
6. Write the fired rules into `severity.likelihood.reason` and `severity.impact.reason` in words, and the full checklist into `<output-dir>/calibration-log.json`.

Precedence, most restrictive first: **force-low > cap-medium > cap-high**. A cap only sets a maximum; it never raises a lower reading.

An `unknown` outcome does **not** apply the cap — stay conservative and keep the higher reading — but record `unknown` with its reason, and note the incomplete calibration in the report.

## 1. Attacker position — a barrier test, not a transport test

`attacker_position` is the outermost boundary the **first untrusted principal** must cross to start. Do not key it on transport. HTTP does not make something external, and the immediate caller is not the attacker when the immediate caller is trusted by design.

If the immediate peer is an internal proxy, gateway, queue, or controller that the design treats as trusted, trace the data flow back to where an untrusted actor actually enters, and use that boundary.

| Value | Meaning |
| --- | --- |
| `external` | Directly reachable from an untrusted network |
| `internal_network` | Reachable only from inside a private network, cluster, or corporate network |
| `in_cluster` | Reachable only from a neighbouring workload in the same cluster |
| `local` | Loopback, unix socket, pipe, shared memory, or local process — including container-to-host, VM escape, and sandbox escape, which are inner-to-outer |
| `host_system` | Outer-to-inner only: a host or hypervisor attacking the software it hosts |
| `supply_chain` | Requires a build-time or dependency-side prerequisite |
| `physical` | Requires physical contact |

**Alignment is mandatory and overrides the threat model's folder-level labels:**

- `local` or `in_cluster` → treat exposure as internal, even where the threat model marks the component externally exposed, **unless** the demonstrated result escapes the container or workload boundary to the host or to another tenant.
- `internal_network` → internal at most.
- `external` → exposed, even where the threat model marks the component internal or privileged.

## 2. Rule catalogue

Record every rule below with an outcome. A rule that fires must carry a one-sentence reason naming the source fact that makes it fire.

### Force-low

The record stays `confirmed` but `overall_severity` is `low` (or `informational` where the result is a prerequisite rather than a consequence in itself).

| Rule | Fires when |
| --- | --- |
| `unreachable_inputs` | The tainted input is documented or demonstrated as not attacker-controlled, and no path from a trust boundary was established. |
| `dependency_unreached` | A dependency defect with no demonstrated path from this application's input to the vulnerable function. |
| `vague_call_path` | The result depends on unverified assumptions about caller behavior or an adjacent component. |
| `unreliable_trigger` | The trigger is ignored in practice, or indistinguishable from normal operation. |
| `prerequisite_equal_privilege` | The attacker already holds execution at the same or higher privilege. Low-to-high escalation instead caps at `medium`. |
| `physical_sustained` | Requires sustained physical access: lab equipment, fault injection, decapping, side-channel rigs. |
| `trusted_controller_zero_delta` | The interface is reachable only from a designed-in authoritative controller (orchestrator→worker, driver→firmware, management→data plane, hypervisor→guest) **and** the result grants that controller zero marginal capability. |
| `host_to_guest_standard` | A host or hypervisor attacking the software it hosts, outside a confidential-computing design. Assume non-confidential-computing unless the source names enclaves, TEE, SEV, TDX, SGX, or attestation. |

Two force-low rules from the source material are **not** used here, because `SKILL.md` disposes of them earlier and better:

- An unreproduced candidate is `needs_validation` with the missing reproduction as its blocker, not a low-severity confirmation. See [REPRODUCTION-LADDER.md](REPRODUCTION-LADDER.md).
- Missing best practice, defense-in-depth, and configuration hygiene are not findings at all. They are `rejected` with the reason "no reachable boundary violation", or hardening notes. Do not emit them as `low` records; anti-patterns 1 and 2 already forbid it.

### Cap at high

| Rule | Fires when |
| --- | --- |
| `exposure_internal` | Every entry path is `internal_network`, `in_cluster`, or `local`. **Exception:** core in-cluster infrastructure (CNI, CSI, admission webhook, service mesh) whose demonstrated result escapes to the node or crosses tenants. Must not fire when `attacker_position` is `external`. |
| `reflected_or_self_xss` | Script execution affects only the requesting user, or requires the victim to deliver their own payload. Stored script execution affecting other users keeps the `high` anchor. |
| `probabilistic_trigger` | Success depends on a non-deterministic component (model output, timing window, memory layout) with no demonstrated way to make it reliable. Cap lifts when unbounded retries without rate limiting or alerting make the non-determinism irrelevant. |
| `supply_chain_prerequisite` | Requires the attacker to already control a build input or dependency. |
| `non_default_configuration` | Requires a configuration that the source does not ship as the default. State the exact setting in `conditions`. |
| `trusted_controller_critical_bypass` | A designed-in controller defeats a documented security or safety limit on the controlled side. No cap when the result reaches a different trust domain or persists across re-provisioning. |
| `confidential_computing_host` | A host attacking an enclave or confidential VM in a design that does claim confidential computing. |

### Cap at medium

| Rule | Fires when |
| --- | --- |
| `local_vector` | Requires a local shell or local user account, with no escape from the workload to the host. |
| `self_contained_blast` | The maximum result is confined to resources the triggering principal already owns or fully controls — their own account, tenant, project, namespace, container, VM, or single-user install — crossing no boundary between mutually distrusting principals. **Do not apply** if it reaches another principal's resources, touches shared or multi-party infrastructure, places the attacker upstream of others (build node, CI runner, registry, model-serving host), or persists past that principal's resource lifecycle into a slot another principal may reuse. Where there is no boundary between distrusting principals at all, the record is `rejected` under anti-pattern 5, not capped. |
| `rarely_exposed` | The surface is reachable only through an interface the source shows as seldom enabled. |
| `equivalent_primitive` | The same principal already has equivalent access through a standard, intended feature. Cap rather than reject, so the defense-in-depth loss stays visible. |
| `documented_insecure` | The component is documented in-repository as diagnostic-only, insecure, or not for production. |
| `physical_brief` | Requires brief physical access: USB insertion, evil-maid. |
| `privileged_external` | `external` entry but the action requires an already-highly-privileged account, with no container escape to the node and no cross-tenant escalation. |
| `trusted_controller_standard_bypass` | A designed-in controller defeats only a sanity or robustness limit, not a security control. |
| `rare_parameter` | The tainted parameter is populated only by rare API shapes, uncommon configuration fields, or data formats seldom processed in practice. Apply to `likelihood.score` first; cap overall only when likelihood alone does not already bring it down. |

### Escalation, applied in step 3 only

**`security_control_bypass`** — the result directly defeats authentication, authorization, or signature verification, or defeats the primary security purpose of the component. Read `impact.score` as at least `high` even where the immediate consequence looks local.

This is an anchor-reading rule, not a capping rule. Apply it in step 3, before `pre_calibration_overall` is recorded, and record it in the checklist for auditability. It never lifts a cap — marginal capability still bounds the outcome — and it is never applied in step 4, where it could only produce a post-calibration reading above the pre-calibration one.

## 3. Absolute gates

- **Critical** requires *all* of: the demonstrated result is code execution or equivalent total loss; the entry principal holds no prior privilege; and no user interaction is required. Zero-click, unauthenticated, total. Where the entry requires a privileged account, cap at `high` even if every other cap was lifted.
- **User interaction required** (CSRF, clickjacking, open-a-file) holds the record below `critical`.
- **Availability-only** results are not `critical` unless the asset carries the `critical` availability tier in `threat-model.md` **and** no automatic recovery — process supervisor restart, load-balancer failover, retry — mitigates the demonstrated stop.
- **Single principal's own data**, with no boundary between mutually distrusting principals crossed, is not a finding at all under anti-pattern 5. That is a verification judgment, not a calibration one: if this pass notices it on a record that already passed Phase 5a, hand the record to a fresh verifier under section 5 rather than rejecting it here. The exception is an action the principal can then deny having taken, or one with side effects on other principals or on system stability — that is a real boundary and is calibrated normally.

## 4. Stale-evidence suppression

When the evidence behind a record may predate the reviewed source ref — a trace from an earlier revision, a check run against a tree whose identity could not be pinned — suppress the four heuristics that a drifted tree makes meaningless and keep the **pre-adjustment, more conservative** reading:

1. Any "proven dead code" de-prioritization: drifted code looks uncalled spuriously.
2. `vague_call_path`: caller behavior re-checked against drifted callers proves nothing. Record `unknown`.
3. Any lift based on an external trace, sanitizer output, or crash log from a prior revision: that is not live reproduction.
4. Any conclusion from a failed check against a drifted tree.

Set `stale_evidence: true` in the calibration log entry, and name it in the report's limitations. It is a flag on the entry, not a checklist rule.

A non-source locator — an endpoint, a symbol, an offset — is not stale evidence; it simply skips the source-only heuristics.

## 5. Viability refutations — verification's job, not calibration's

**Calibration never changes a verdict.** The tests below belong to the Phase 3 and Phase 5a verifiers, which have the source in front of them and the independence the verdict requires. They are stated here because they are the reason a record that looks severe is often not a record at all, and because a calibrator who notices one must do something with it.

Give these to verifiers as refutation tests:

| Refutation | Verdict | Notes |
| --- | --- | --- |
| Out-of-bounds access contained within the allocation's own padding or safety margin | `rejected` | Locate and cite the allocation source. |
| Relies on `assert()`, `debug_abort()`, or a development-only panic that the release build strips | `rejected` | Cite the build flag that strips it. |
| Behind conditional compilation for a debug build | `rejected` | Cite the guard. |
| A mock authentication provider, debug backdoor, or test-only route excluded from a normal build | `rejected` | Cite where it is excluded. |
| Blocked by an environmental control (OS permissions, kernel sandboxing, read-only filesystem) **that the repository itself defines** — an in-tree systemd hardening unit, a `read_only` container spec, a checked-in seccomp profile | `rejected` | Cite the in-tree control. |
| Blocked by an environmental control the repository does not contain | `needs_validation` | A deployment fact. "Respect source visibility" forbids assuming either presence or absence; name the missing fact as the blocker. |
| Reachable only under a non-default configuration or optional build flag | `confirmed` with the configuration in `conditions` and `non_default_configuration` capping it — or `needs_validation` when whether that configuration is enabled is a deployment fact absent from source | — |
| Lives only in examples, tests, or fuzz harnesses **and no production principal can reach it** | `rejected` | The unreachability must be established from source. A file path under `tests/` is a label, not a reachability argument; where a demonstrated boundary violation is reachable, it stays `confirmed`, capped by `documented_insecure` or `self_contained_blast`. |

**If this pass notices a refutation on a record that already passed Phase 5a**, do not reject it here. Treat it as a material replacement under the Phase 5 rule in [VALIDATION-AND-REPORTING.md](VALIDATION-AND-REPORTING.md): hand the record to a fresh verifier that did not hunt it, did not validate it, and did not propose the refutation. If budget or independence is unavailable, remove the disputed record from `findings.json`, keep its ledger unit an unresolved candidate, and set `run_status: "incomplete"` with an exact reason. Never delete an independently verified finding on a parent-side judgment.

**Drift fail-safe:** a missing file, an out-of-range line, or evident code drift must never produce a rejection. A missing file is not dead code. Keep the record, state the drift as the reason the check was inconclusive, and re-verify against current source.

## 6. Recording

`report-schema.json` is `additionalProperties: false`. Do not add `impact_score`, `likelihood_score`, `risk_score`, `priority`, `attacker_position`, `availability_tier`, or `calibration_checklist` to any record. There is no numeric score anywhere in this workflow: any arithmetic is a private ordering heuristic, and `overall_severity` is read from the anchors, never from a band lookup.

Express the outcome through the existing fields:

- `severity.likelihood.reason` and `severity.impact.reason` name the rules in words — "capped at medium: self-contained blast radius, the result stays inside the triggering tenant's own namespace".
- `conditions` carries any configuration or precondition that a cap depends on.
- `confidence.reason` carries an `unknown` calibration outcome.

Write the machine-readable checklist to `<output-dir>/calibration-log.json`, parent-owned:

```json
{
  "fingerprint": "<from findings.json>",
  "attacker_position": "external|internal_network|in_cluster|local|host_system|supply_chain|physical",
  "pre_calibration_overall": "informational|low|medium|high|critical",
  "post_calibration_overall": "informational|low|medium|high|critical",
  "cap_applied": "<rule name, or null>",
  "stale_evidence": false,
  "checklist": [
    { "rule": "self_contained_blast", "outcome": "applies|does_not_apply|unknown", "reason": "..." }
  ]
}
```

`post_calibration_overall` must equal the record's `severity.overall_severity` and must never exceed `pre_calibration_overall`. Both are checked by `validate-companion-artifacts.cjs`.

## Anti-patterns specific to this file

1. Raising a severity during calibration.
2. Assigning or adjusting severity on a `needs_validation` record.
3. Emitting a `low` record for hygiene, defense-in-depth, or an unreproduced candidate.
4. Reading `attacker_position` off the transport or off the immediate caller.
5. Producing a numeric risk score, or letting likelihood push the overall level above demonstrated impact.
6. Applying a cap on an `unknown` outcome.
7. Rejecting a record because the cited file or line drifted, or rejecting one during calibration at all rather than handing it to a fresh verifier.
8. Letting a deployment-intent verdict, a folder label, or a threat-model heading override a demonstrated result.
