# Native Windows security scope

The Rust controller replaces the former C#, C, PowerShell and Python bootstrap.
Its required `windows_native` test target runs on Windows. Portable policy tests
and cross compilation do not establish native containment.

The required probe starts from a restricted LUA primary token with the complete
Administrators SID marked deny-only, creates a zero-capability LPAC, and keeps
the child suspended until it belongs to its owned job and its dangerous
privileges have been removed. The job enforces process, memory, CPU time and CPU
rate limits; the controller enforces an output budget and wall deadline. Exactly
three standard handles are inherited. The retained native Rust verifier checks
the actual primary and descendant tokens, detached standard handles, job
membership, privilege LUIDs and bounded registry identities.

The positive registry fixture is a fresh random key under the current user's
`Software` key. The package receives read access to that root only. A protected
private child, mutation rights and a separately protected private file must
remain inaccessible. Both process generations also perform a create-only,
exact-byte scratch read/write control whose handle deletes its own object on
close. Scratch ACLs reject package permission/owner changes and grant only the
concrete package. Prepared images are read-only at medium integrity. Existing
registry policies are never modified. Every successful fixture receipt includes
`"scope":"owned-fixture"` and `"foreign_file_denied":true`.

The controller also establishes real host-positive IPv4/IPv6 TCP and UDP loopback
endpoints. Both LPAC generations must receive the exact native access-denied
socket error for all four families/transports. These checks are reported as
`"network_denied":true`; successful create-only scratch controls are reported as
`"scratch_write":true`. A timeout, unavailable host endpoint, or another socket
error cannot count as network denial.

Cleanup kills and reaps the whole job before closing process handles or deleting
owned registry keys, scratch directories and the newly created profile. Registry
deletion uses the retained native key handle. Cleanup failures are fatal and an
earlier operation failure remains in the error chain. Protected path preparation
rejects reparse points; file preparation and publication verify native object
identities.

The 82 former portable Windows test cases are mapped to 82 Rust cases in
`crates/revayat-scientific/tests/windows_contract/`. Six additional required
Windows cases exercise actual LPAC authority, host refusal, job ownership,
process lifetime, reparse rejection and persisted scratch ACLs. The original
authority protocol, pipe, process, token and cleanup tests remain. Its independent
41-case source oracle is now generated from Rust; it needs no interpreter or
environment-variable fixture file.

The removed infrastructure tested CPython/.NET loader initialization, Python
activation contexts, CSR callbacks, debugger loader snaps and ETW/SxS causality.
Those interpreters are absent from the native product, but removing them does
not by itself complete the original test obligations. Native counterparts,
their operation relationships and actual execution evidence remain required by
the migration censuses. VHD quota, volume attachment and machine-wide SideBySide
diagnostics are not currently established by the narrow owned-fixture gate.
The former machine-registry diagnostic remains the verifier's explicit default
mode; it is not the required owned-fixture gate and receives no automatic host
ACL grants. Owned-fixture success makes no claim about machine SideBySide
access, VHD disk quotas, ETW traces, or interpreter activation.

The native-stage collector and several census contracts remain unfinished; see
the [outstanding acceptance gates](../../../docs/development.md#outstanding-acceptance-gates).
Passing the six native gate cases is not a complete Windows migration result.

Normal document tools use a job to own their process trees. This lifetime
ownership does not itself provide an LPAC file or network sandbox. The required
LPAC gate attests its fixed verifier workflow, not every external renderer.

Run the gate after building all workspace targets:

```text
cargo build --locked --workspace --all-targets
cargo test --locked --workspace --all-targets -- --test-threads=1
```

There are no ignored or optional cases in `windows_native`; a missing verifier
binary or failed native containment proof fails the gate.
