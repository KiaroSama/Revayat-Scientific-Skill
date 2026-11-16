This fixture preserves the genuine non-debug x64 CPython 3.11
subject. It is separate from the Rust registry-authority executable and the
`_registry_loader` followup module.

`import_dispatch.py` is the entire residual Python source: the eight actual
imports from `RegistryAuthorityProbe.py@4e24f3d:121–139`, the original exception
object, and one dispatch into the owned Rust extension. It contains no token,
registry, descendant, classification, or reporting logic. The Rust module is
loaded only after those imports finish or raise. A failure to load that module
is fatal and cannot mint a qualified bootstrap receipt.

The Rust C-API body must create, retain, configure, and call genuine ctypes
objects for the original ctypes/ABI obligations. Direct Rust Win32 calls are
not evidence of those Python-specific obligations. The original provider's
`_ctypes.pyd` and `libffi-8.dll` remain unchanged external dependencies.

The pinned Rust producer compiles the C-API body against the genuine runtime's
own import library and retains the dispatcher and dependency identities. It
shares the reviewed native memory helpers and real x64 stack probe with the
activation fixtures. Full native orchestration, host-positive controls and
actual child observations remain required for admission. Cross-linking, a
successful import or portable source validation cannot establish that evidence.
