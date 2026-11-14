//! Actual pinned Rust source digests; historical C digests are not executable proofs.
//! Rust-to-Rust repairs: EMIT keeps exact frames/256-byte bounds/exit121 using checked access.
//! BUILTINS uses real Win64 leaf memory loops; other hosts retain the portable C ABI implementation.
//! MODULE_DLL preserves the full parser matrix with bounded copies and exact acquire/release MOVs.
pub const ABI_SHA256: &str = "e30e5528e4517b1fc9adad4127522ae5992a5ed666bda0c4c2d6a9a9aef3e76b";
pub const EMIT_SHA256: &str = "ae678879db01c3cd41121e7e155cfb121a6bb131bf8d2f4d2616a21956fd7e60";
pub const BUILTINS_SHA256: &str =
    "fe89d755b1cf1e834b3061b757a5226bd17f3de26145cb92abc11ac70224b86b";
pub const STACK_PROBE_SHA256: &str =
    "9576de1b45d3d95ee552956fb2bdfadf28abb09e9c7e4df0223423280b180ee8";
pub const CHILD_SHA256: &str = "86c19ca7da3d9ecded65f11fc9566b542b5f5d2ea165c076ff76f66544d510e4";
pub const SELF_SHA256: &str = "5b5c5722345ff83b37702dbc32dfade5c4e2f3597bcd77fa15fc79e87d7a211c";
pub const DEFAULT_SHA256: &str = "0140d85087706b31562c5b5a676cc606e1e0267efa36140875e2775f29095f88";
pub const MODULE_HOST_SHA256: &str =
    "8f9d59cb9f60f4ce180fa7ba6276c788a43d7d5bb3ce506c8c7fb36428ae048c";
pub const MODULE_DLL_SHA256: &str =
    "e9f119cdcfd078422dac2b3e98b90e421697cc2bf8d1faee7408885210de80e9";
pub const STARTUP_ENTRY_SHA256: &str =
    "81b96d3763d25e7de09657a4b338ee2fe02e7985ca49cec97811f7f130425682";
pub const MODULE_ENTRY_SHA256: &str =
    "22c819efdeebe791f7b23ac295a9c70ebf0747edf9b568f56398cb207dffb033";
pub const MANUAL_SHA256: &str = "007969e0a56a6dbebb3197029e1bc34f8d58488e4ba0d4b1728037165254beec";
pub const EXPLICIT_SHA256: &str =
    "e309235c8b4fb9ce49d1068629ee25d6aea84151fd4f1aadbf9a56fc6f07c7d7";
