//! Verifier flags attached to every opcode row.
//!
//! The names mirror ART's `VerifyFlag` enum (`dex_instruction.h`) and the
//! generated table combines them the same way ART does, but the **bit values
//! are internal to this crate** (assigned in enum order) and do not match
//! ART's numbering; never compare them with values read from ART binaries.
//! Only `VERIFY_SWITCH_TARGETS`, `VERIFY_ARRAY_DATA` and
//! `VERIFY_BRANCH_TARGET` are inspected at runtime
//! (`Opcode::references_payload`, `Opcode::is_branch`); the rest are kept so
//! the table stays a faithful transcription of ART's.

pub const VERIFY_NOTHING: u32 = 1 << 0;
pub const VERIFY_REG_A: u32 = 1 << 1;
pub const VERIFY_REG_B: u32 = 1 << 2;
pub const VERIFY_REG_A_WIDE: u32 = 1 << 3;
pub const VERIFY_REG_B_WIDE: u32 = 1 << 4;
pub const VERIFY_REG_B_STRING: u32 = 1 << 5;
pub const VERIFY_REG_B_TYPE: u32 = 1 << 6;
pub const VERIFY_REG_C_TYPE: u32 = 1 << 7;
pub const VERIFY_REG_B_NEW_INSTANCE: u32 = 1 << 8;
pub const VERIFY_REG_C_NEW_ARRAY: u32 = 1 << 9;
pub const VERIFY_REG_B_FILLED_NEW_ARRAY: u32 = 1 << 10;
pub const VERIFY_VAR_ARG: u32 = 1 << 11;
pub const VERIFY_VAR_ARG_RANGE: u32 = 1 << 12;
pub const VERIFY_ARRAY_DATA: u32 = 1 << 13;
pub const VERIFY_BRANCH_TARGET: u32 = 1 << 14;
pub const VERIFY_SWITCH_TARGETS: u32 = 1 << 15;
pub const VERIFY_REG_C: u32 = 1 << 16;
pub const VERIFY_REG_C_WIDE: u32 = 1 << 17;
pub const VERIFY_ERROR: u32 = 1 << 18;
pub const VERIFY_REG_C_FIELD: u32 = 1 << 19;
pub const VERIFY_REG_B_FIELD: u32 = 1 << 20;
pub const VERIFY_REG_B_METHOD: u32 = 1 << 21;
pub const VERIFY_VAR_ARG_NON_ZERO: u32 = 1 << 22;
pub const VERIFY_VAR_ARG_RANGE_NON_ZERO: u32 = 1 << 23;
pub const VERIFY_REG_H_PROTOTYPE: u32 = 1 << 24;
pub const VERIFY_REG_B_CALL_SITE: u32 = 1 << 25;
pub const VERIFY_REG_B_METHOD_HANDLE: u32 = 1 << 26;
pub const VERIFY_REG_B_PROTOTYPE: u32 = 1 << 27;
