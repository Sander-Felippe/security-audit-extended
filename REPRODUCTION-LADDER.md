# Reproduction Ladder

Read this in Phase 2 before assigning a hunter that intends to execute anything, and in Phase 3 before a verifier reproduces a decisive check. In guidance mode, use it to say what a given piece of evidence is allowed to claim.

This file grades local evidence. It does not relax any control in `SKILL.md` "Universal execution safety" — every rung above R0 runs inside the full OS-enforced sandbox, and if one control cannot be enforced, nothing executes.

**This audit never modifies the target.** It has no patch step, no remediation-verification loop, and no re-attack pass. It describes the smallest effective source fix and stops.

## The rungs

| Rung | Name | Evidence | May claim |
| --- | --- | --- | --- |
| R0 | Source trace | Entrypoint, propagation, sink, and the source-visible controls on the path | A source-grounded hypothesis and its blocker. Nothing about runtime behavior. |
| R0.5 | Structural reachability | An AST or index call path from a public entrypoint to the sink | Nothing. Ordering hint only. |
| R1 | Micro-harness | Direct call of the function or module in isolation | The hypothesis is sound in isolation. Never a reproduction verdict. |
| R2 | Subsystem validation | The input survives the real intermediate processing unchanged | The input reaches the subsystem boundary intact. Never a reproduction verdict. |
| R3 | Bounded local harness at the real interface | The target's own interface produces the minimum boundary result on a dummy principal or resource | `confirmed`, at severity capped by the demonstrated result. |
| R3a | Local middlebox annotation | R3 input replayed through a proxy, gateway, or WAF built from the repository's own config files, in the same sandbox | Annotation only. |

**R3 is the ceiling.** Staging, pre-production, and any other deployed or shared environment are out of scope entirely: they probe infrastructure this audit does not own. A fact that only such an environment could settle is a `needs_validation` blocker with an owner-observed plan — and the report never contains live-probe instructions.

### Rung rules

- **A `confirmed` record requires R3.** R0 through R2 results are `needs_validation`, with the rung reached and the exact promotion blocker named. There is no "statically confirmed" verdict; a static claim never wears a reproduction label.
- **R0.5 may never reject anything.** An absent call path is not absence of a call: call graphs miss macros, function pointers, dynamic dispatch, and virtual tables. Use it to order work, never to skip a candidate or set a negative verdict.
- **R1 and R2 never yield a reproduction verdict**, however clean the result. Promote R1 → R2 when the same input survives the real input path (serialization, parser, router, auth wrapper) unchanged. Promote R2 → R3 when the payload is deliverable through the component's real public interface without harness tricks.
- **Internal-invariant guard.** If the effect is reachable only by feeding a private or static function a hand-built buffer that the component's own execution invariants would never produce — allocating 15 bytes where the library guarantees `rowbytes + 48` — do not claim reproduction. Record the blocker as an internal invariant protection and keep `needs_validation`.
- **R3a never changes a verdict.** A block at the local middlebox does not downgrade the R3 result; record it as a condition that narrows likelihood or impact. A pass does not upgrade severity. Never assume anything about a middlebox that is not built from the repository's own configuration; deployed proxy behavior is a `needs_validation` fact under "Respect source visibility".
- **Escalate reachability, never impact.** Climbing the ladder is about showing the real interface reaches the defect. It is never about making the consequence bigger. "Stop at the minimum boundary result" still governs at every rung.

## Reached-sink evidence gate

Before recording any result — and mandatory before any *negative* result — establish which of two channels proves the sink was reached:

- **(a) Source or script harness** — write the exact bytes of an in-path sentinel to a sidecar file in `scratch/`, flushed and fsynced (or written unbuffered), **before** invoking the sink. A file survives a crash that truncates buffered stdout.
- **(b) Binary or opaque target** — a target-produced crash backtrace or sanitizer frame that **names the sink function**.

A marker your own wrapper wrote before launching the target is setup evidence only: it proves launch was attempted, not that the sink was reached.

Evidence is absent on any nonzero build or compile exit, on exit 127 (command not found), and on exit 2 with "No such file". With evidence absent, record "not attempted, retry-eligible" and stop. **Never synthesize the marker.** A build or setup failure written down as "did not reproduce" silently drops a real defect.

Sanitizers: scan stdout and stderr for ASan, UBSan, and TSan signatures **regardless of exit code** — UBSan recovers and exits 0. Build memory-safety and undefined-behavior candidates with `-fsanitize=address,undefined -fno-omit-frame-pointer`, and TSan as a separate build. Do not use `-fsanitize=memory` unless the whole dependency chain including libc is MSan-instrumented; an uninstrumented MSan trace is not evidence. Use identical sanitizer flags across every run being compared.

## Capability checks

Run each check before execution, not during, and record the exact failing capability.

- R0 is always reachable.
- Hardware virtualization: `/dev/kvm` readable and writable.
- Container engine on PATH, with the required runtime registered (for example `info --format '{{json .Runtimes}}'` listing `runsc`), and `image inspect <image>` succeeding against the **local** cache.
- Image policy is never-pull. A missing image is a capability failure, not a reason to fetch or build one.
- Network isolation asserted at creation (`--network=none` or equivalent), not checked afterwards — and never asserted by dialing an address. Never contact `169.254.169.254`, a public resolver, or any external host to "prove" isolation; assert it from the sandbox configuration.
- Source identity: the tree under test matches the resolved `source_ref`. On mismatch, regenerate the harness from current source and never reuse stored line numbers, offsets, or addresses.
- Toolchain: the required compiler, interpreter, or sanitizer is already installed. Missing is a capability failure, never an install.

When a rung is unreachable, record the exact missing capability as a `needs_validation` blocker ("sandbox capability: no `runsc` runtime registered"), keep the candidate at the highest rung actually achieved, and give a safe validation plan. **Never downgrade an unverified candidate to `rejected` on a capability failure**, and never treat a negative result as authoritative when the tree's identity could not be pinned.

## Environment tiers

| Tier | Isolation | Against the control list in `SKILL.md` |
| --- | --- | --- |
| Static only | Nothing executes; path-confined read-only reads that refuse symlink components, traversal, multiply-linked files, VCS directories, and credential files | Satisfies — it is R0 |
| Local microVM (KVM-backed) | Guest VM, no host filesystem mounts, no network, target copied into the guest, destroyed on close | Satisfies once explicit CPU, memory, process, file-size, disk, and wall-clock limits are set. A 30-second command timeout alone is not the limit set. |
| Hardened container runtime (for example gVisor) | OCI container under a syscall-interposing runtime, no network, no host mounts, pid/memory/cpu limits, removed on close | Satisfies with limits tightened to explicitly low values and file-size and disk caps added. Multi-gigabyte, multi-core defaults are a ceiling, not a low limit. |
| Remote cloud VM | Hardened but remote | **Does not satisfy.** Needs external network to provision, spends paid quota, runs on shared infrastructure. Drop. |
| Staging or pre-production | Human-gated access to real systems | **Does not satisfy.** Deployed and shared. Drop. |

Whatever the tier, stage only vetted files into the sandbox: do not follow symlinks, refuse symlinked leaves and symlinked intermediate components, refuse multiply-linked files, enforce containment of the real path against the resolved target, and never stage `.git`, `.hg`, `.svn`, `.jj`, `.env*`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.gitconfig`, `.gitmodules`, or pre-commit configuration.

## Keeping a reproducer from becoming a weapon

- **No persistence.** The environment is per-run and destroyed on close. Nothing a target-controlled process wrote survives except allowlisted files promoted by trusted parent-side code after every sandbox process has terminated.
- **No lateral movement.** No network, no host filesystem mounts, no host command execution, no access to another agent's directory, the output directory, the host home, sockets, or shared services.
- **No exfiltration.** No egress, no DNS, no metadata endpoint. Credential and VCS files are never staged in at all.
- **Dummy principals and dummy secrets only.** Never a real token, never another user's data, never a production identity.
- **Stop at the minimum effect** — a wrong return value, an unauthorized dummy record, a sanitizer finding, a policy difference. Do not continue past it, do not infer a stronger result, and do not produce persistence, post-fault, or concealment material.
- **No variant hunting.** Do not generate boundary-mutated payload families, encoding variants, alternate endpoints, or role variants to see what else trips. That is patch grading, and this audit does not patch.

## Recording the rung

`report-schema.json` is `additionalProperties: false`. Add no `rung` key to any record. Three carriers, in order of preference:

1. **The coverage ledger.** Prefix the check's existing `invariant` with a canonical rung token: `"[R3] parser rejects oversized length before copy"`. R0 and R0.5 checks use `method: "source"` with `artifact: null`; R1 through R3a use `method: "local"` with an artifact under `agents/<check.agent_id>/artifacts/`. This is already validated for ownership and path safety.
2. **`<output-dir>/reproduction-ladder.json`**, parent-owned, keyed by fingerprint:

```json
{
  "fingerprint": "<from findings.json>",
  "rung_reached": "R0|R0.5|R1|R2|R3|R3a",
  "rung_attempted": "R0|R0.5|R1|R2|R3|R3a",
  "evidence_channel": "a|b|null",
  "environment_tier": "static|microvm|hardened_container",
  "capability_blocker": "<exact missing capability, or null>"
}
```

3. **Prose.** A `confirmed` record's `execution.observed_result` is free text and may open with the rung in words. Never invent a key inside a record.

A rung label never implies coverage the ledger does not carry.

## Anti-patterns specific to this file

1. Recording a `confirmed` verdict below R3.
2. Writing "did not reproduce" after a build, setup, or capability failure.
3. Using an absent call path to reject or skip a candidate.
4. Claiming reproduction through a harness that bypasses the component's own execution invariants.
5. Proving network isolation by making a network request.
6. Fetching or building a sandbox image, or installing a toolchain, to reach a higher rung.
7. Escalating a reproducer past the minimum boundary result, or generating payload variants.
8. Treating a local middlebox result, or an assumption about a deployed proxy, as a severity change.
