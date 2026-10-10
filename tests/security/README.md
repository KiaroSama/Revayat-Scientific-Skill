# Bounded security regression tiers

These authored tests address specific source-audit hypotheses, not every possible vulnerability or container escape. `coverage.json` binds the exact scenarios and explicitly excludes Microsoft Word, external agent consent/provenance and real manuscript fidelity.

## Execution order

`Security regressions` prepares existing runtime dependencies outside the reviewed-code phase. Each required job then proves effective kernel controls before importing target helpers or processing fixtures. Missing controls fail the job; there are no successful prerequisite skips or unrestricted fallbacks.

- Linux uses a read-only prepared image/target, no network, non-root identity, dropped capabilities, no-new-privileges, CPU/memory/PID limits, per-file limits and bounded scratch tmpfs. The trusted image-owned probe checks environment equality, mount write refusal, namespace/cgroup/ulimit values, permitted scratch and sparse per-file rejection. Only fixed scenario scripts execute after the probe.
- Windows requires real Python 3.11, profileless LPAC with no capabilities, read-only copied runtime/target ACLs, explicit safe environment, Job Object ownership/resource bounds and a uniquely created disposable NTFS virtual disk. Its 128 MiB physical capacity and 16 MiB per-owner logical quota are distinct limits; multiple owner entries do not imply a 16 MiB volume-wide quota. The suspended worker token's privileges and assignable owner identities are constrained and checked before resume, with finite quota entries for every permitted owner and the default. Protected-creator and owner-selection controls verify that private scratch permission changes cannot bypass logical quotas or modify protected target/runtime, scratch-root or volume controls. Native EOF and ordinary/sparse positive/negative cases distinguish an effective limit from a configured one. Trusted controls run before native junction/public-adapter and existing WindowsBase OPC cases. A mocked attribute check is not native junction evidence.

## Fixtures and assertions

All fixtures are harmless authored scientific/document/package data. DOCX relationship cases preserve original bytes and prior-output sentinels; supported and external-data edits are controls. HTML finite depth/cardinality cases cover parser, Source, guard, assets, text order, resource policy, public lint and the actual render-worker admission entry. The renderer backend is mocked only for admission ordering: refused inputs never invoke it, ordinary nesting does. This is not full rendering verification. Output-link cases protect outside sentinels. TeX writes only two tiny public text files and an ordinary PDF; finite tmpfs reservation verifies the outer aggregate budget without exhausting the host volume.

The outer test sandbox's aggregate quota does **not** prove that production TeX's writable output bind has an aggregate quota. Production controls and actual consumer policy must be reported separately; tests never upgrade a hypothesis to a confirmed security result merely from configuration.

## Logs, bounds and cleanup

Linux parent logs are UTF-8 in `logs/security-ci_YYYY-MM-DD_HH-MM-SS_UTC.log`, collision-safe, with UTC timestamp/level/component fields. The worker logs inside owned scratch; no source bodies, credentials or private environment values are logged. Windows setup logs are UTF-8 per run under the owned security log directory. Initialization failure is explicit, and handlers close on every exit.

Linux diagnostics are capped at 1 MiB; child/container wall deadlines are 90/110 seconds with a 20-second parent idle bound plus owned cleanup. Windows compiler/setup execution is wrapped by a stdlib-only outer Job owner (300-second wall, 45-second idle, 1 MiB combined output); fixed cleanup has separate 30/15-second bounds. Individual native preparation tools have 60/20-second bounds. Native worker budgets are recorded and queried by its controller; required controls must be observed before the target phase. Cleanup touches only the exact label/name/ID or the uniquely created Windows disk/profile/job state. Useful failed-run logs remain for diagnosis; disposable scratch is removed after termination.

## Current evidence

Authored tests are not execution evidence. Before the first exact-SHA hosted run, native controls and regression red/green results are unverified. A failing admission assertion is retained for a root fix, not changed to a skip or unconditional success. Review the actual job output and scenario IDs before claiming completion.
