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

/// ART `kVerifyNothing` (`kVerifyNone` in newer ART): no operand to check.
pub const VERIFY_NOTHING: u32 = 1 << 0;
/// ART `kVerifyRegA`: `A` is a register.
pub const VERIFY_REG_A: u32 = 1 << 1;
/// ART `kVerifyRegB`: `B` is a register.
pub const VERIFY_REG_B: u32 = 1 << 2;
/// ART `kVerifyRegAWide`: `A` is the low register of a wide pair.
pub const VERIFY_REG_A_WIDE: u32 = 1 << 3;
/// ART `kVerifyRegBWide`: `B` is the low register of a wide pair.
pub const VERIFY_REG_B_WIDE: u32 = 1 << 4;
/// ART `kVerifyRegBString`: `B` is a `string_ids` index.
pub const VERIFY_REG_B_STRING: u32 = 1 << 5;
/// ART `kVerifyRegBType`: `B` is a `type_ids` index.
pub const VERIFY_REG_B_TYPE: u32 = 1 << 6;
/// ART `kVerifyRegCType`: `C` is a `type_ids` index.
pub const VERIFY_REG_C_TYPE: u32 = 1 << 7;
/// ART `kVerifyRegBNewInstance`: `B` is the type index of `new-instance`.
pub const VERIFY_REG_B_NEW_INSTANCE: u32 = 1 << 8;
/// ART `kVerifyRegCNewArray`: `C` is the array type index of `new-array`.
pub const VERIFY_REG_C_NEW_ARRAY: u32 = 1 << 9;
/// ART `kVerifyRegBFilledNewArray` (older ART): `B` is the array type of `filled-new-array`.
pub const VERIFY_REG_B_FILLED_NEW_ARRAY: u32 = 1 << 10;
/// ART `kVerifyVarArg`: `35c` argument list of up to five registers.
pub const VERIFY_VAR_ARG: u32 = 1 << 11;
/// ART `kVerifyVarArgRange`: `3rc` argument register range.
pub const VERIFY_VAR_ARG_RANGE: u32 = 1 << 12;
/// ART `kVerifyArrayData`: `B` is a relative offset to a `fill-array-data-payload`.
pub const VERIFY_ARRAY_DATA: u32 = 1 << 13;
/// ART `kVerifyBranchTarget`: the instruction has a relative branch target.
pub const VERIFY_BRANCH_TARGET: u32 = 1 << 14;
/// ART `kVerifySwitchTargets`: `B` is a relative offset to a switch payload.
pub const VERIFY_SWITCH_TARGETS: u32 = 1 << 15;
/// ART `kVerifyRegC`: `C` is a register.
pub const VERIFY_REG_C: u32 = 1 << 16;
/// ART `kVerifyRegCWide`: `C` is the low register of a wide pair.
pub const VERIFY_REG_C_WIDE: u32 = 1 << 17;
/// ART `kVerifyError`: the opcode is always a verification error (not set by this table).
pub const VERIFY_ERROR: u32 = 1 << 18;
/// ART `kVerifyRegCField`: `C` is a `field_ids` index.
pub const VERIFY_REG_C_FIELD: u32 = 1 << 19;
/// ART `kVerifyRegBField`: `B` is a `field_ids` index.
pub const VERIFY_REG_B_FIELD: u32 = 1 << 20;
/// ART `kVerifyRegBMethod`: `B` is a `method_ids` index.
pub const VERIFY_REG_B_METHOD: u32 = 1 << 21;
/// ART `kVerifyVarArgNonZero`: `35c` argument list with at least one register.
pub const VERIFY_VAR_ARG_NON_ZERO: u32 = 1 << 22;
/// ART `kVerifyVarArgRangeNonZero`: `3rc` range with at least one register.
pub const VERIFY_VAR_ARG_RANGE_NON_ZERO: u32 = 1 << 23;
/// ART `kVerifyRegHPrototype`: `H` is a `proto_ids` index (`invoke-polymorphic`).
pub const VERIFY_REG_H_PROTOTYPE: u32 = 1 << 24;
/// ART `kVerifyRegBCallSite`: `B` is a `call_site_ids` index.
pub const VERIFY_REG_B_CALL_SITE: u32 = 1 << 25;
/// ART `kVerifyRegBMethodHandle`: `B` is a `method_handles` index.
pub const VERIFY_REG_B_METHOD_HANDLE: u32 = 1 << 26;
/// ART `kVerifyRegBPrototype`: `B` is a `proto_ids` index.
pub const VERIFY_REG_B_PROTOTYPE: u32 = 1 << 27;
