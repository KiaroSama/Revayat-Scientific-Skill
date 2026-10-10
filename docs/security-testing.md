# Security regression evidence

The separate `Security regressions` workflow has mandatory Linux and Windows tiers. It supplements ordinary portable/native document tests, CodeQL and dependency checks; none replaces a full source-and-runtime security engagement.

The finite scenario ledger is [tests/security/coverage.json](../tests/security/coverage.json), with fixture/control/containment documentation in [tests/security/README.md](../tests/security/README.md). It covers package relationship case identity, output links including native Windows/Python 3.11 junctions, shared HTML parser work admission across callers, and bounded TeX output observations. Independent WindowsBase OPC observation is not a claim about Microsoft Word behavior.

Prepared runtimes and trusted kernel probes precede reviewed document/helper execution. Any missing isolation control fails closed, without executing the target phase. Required native cases cannot be converted into green skips. Tiny authored fixtures and dummy sentinels are the only test data; no credentials, deployed endpoints, stress payloads or real user manuscripts are needed.

## Evidence boundaries

- A requested container option is not an observed kernel control.
- A mock reparse attribute is not a native junction result.
- A case-insensitive package API is not proof of every Office consumer.
- An outer scratch quota is not production TeX output-bind quota.
- A mechanical result, artifact hash or clean CI is not user consent or semantic translation approval.

Only the exact tested revision, actual prerequisite observations, load-bearing positive/negative assertions and owned cleanup support a completion claim. Source-audit hypotheses remain unresolved until their decisive facts are observed or independently refuted. All limits must be named in the job/report rather than hidden by `continue-on-error`.

## Diagnostic logs

Parent controllers write one UTF-8 UTC log per run, without document bodies or secret values. Linux uses `logs/security-ci_YYYY-MM-DD_HH-MM-SS_UTC.log`; Windows uses the owned security log directory described in the test README. Entries use `[timestamp UTC] [LEVEL] [COMPONENT] Message`. Logs record setup, effective controls, scenario transitions, exit status, duration and cleanup; logging failures are explicit. Preserve failed-run diagnostics locally, and share only a reviewed redacted log when requesting support. There is no automatic log upload or retention service.
