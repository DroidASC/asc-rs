// Generated from droidasc/asc_core/models/dvm_opcode.py (ART dex_instruction_list.h). Do not edit by hand.
use crate::verify::*;
use crate::{Format, IndexKind, Opcode};

const fn op(value: u8, name: &'static str, len: u8, format: Format, index: IndexKind, verify: u32) -> Option<Opcode> {
    Some(Opcode { value, name, len, format, index, verify })
}

/// Dalvik opcode table indexed by the opcode byte.
pub static OPCODES: [Option<Opcode>; 256] = OPCODE_TABLE;

/// Compile-time copy of the table so derived lookup tables (`LEN`) can be
/// evaluated in `const` context.
pub(crate) const OPCODE_TABLE: [Option<Opcode>; 256] = [
    op(0x00, "nop", 1, Format::K10x, IndexKind::None, VERIFY_NOTHING), // 0x00
    op(0x01, "move", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x01
    op(0x02, "move/from16", 2, Format::K22x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x02
    op(0x03, "move/16", 3, Format::K32x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x03
    op(0x04, "move-wide", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x04
    op(0x05, "move-wide/from16", 2, Format::K22x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x05
    op(0x06, "move-wide/16", 3, Format::K32x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x06
    op(0x07, "move-object", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x07
    op(0x08, "move-object/from16", 2, Format::K22x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x08
    op(0x09, "move-object/16", 3, Format::K32x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x09
    op(0x0A, "move-result", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x0a
    op(0x0B, "move-result-wide", 1, Format::K11x, IndexKind::None, VERIFY_REG_A_WIDE), // 0x0b
    op(0x0C, "move-result-object", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x0c
    op(0x0D, "move-exception", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x0d
    op(0x0E, "return-void", 1, Format::K10x, IndexKind::None, VERIFY_NOTHING), // 0x0e
    op(0x0F, "return", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x0f
    op(0x10, "return-wide", 1, Format::K11x, IndexKind::None, VERIFY_REG_A_WIDE), // 0x10
    op(0x11, "return-object", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x11
    op(0x12, "const/4", 1, Format::K11n, IndexKind::None, VERIFY_REG_A), // 0x12
    op(0x13, "const/16", 2, Format::K21s, IndexKind::None, VERIFY_REG_A), // 0x13
    op(0x14, "const", 3, Format::K31i, IndexKind::None, VERIFY_REG_A), // 0x14
    op(0x15, "const/high16", 2, Format::K21h, IndexKind::None, VERIFY_REG_A), // 0x15
    op(0x16, "const-wide/16", 2, Format::K21s, IndexKind::None, VERIFY_REG_A_WIDE), // 0x16
    op(0x17, "const-wide/32", 3, Format::K31i, IndexKind::None, VERIFY_REG_A_WIDE), // 0x17
    op(0x18, "const-wide", 5, Format::K51l, IndexKind::None, VERIFY_REG_A_WIDE), // 0x18
    op(0x19, "const-wide/high16", 2, Format::K21h, IndexKind::None, VERIFY_REG_A_WIDE), // 0x19
    op(0x1A, "const-string", 2, Format::K21c, IndexKind::StringRef, VERIFY_REG_A | VERIFY_REG_B_STRING), // 0x1a
    op(0x1B, "const-string/jumbo", 3, Format::K31c, IndexKind::StringRef, VERIFY_REG_A | VERIFY_REG_B_STRING), // 0x1b
    op(0x1C, "const-class", 2, Format::K21c, IndexKind::TypeRef, VERIFY_REG_A | VERIFY_REG_B_TYPE), // 0x1c
    op(0x1D, "monitor-enter", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x1d
    op(0x1E, "monitor-exit", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x1e
    op(0x1F, "check-cast", 2, Format::K21c, IndexKind::TypeRef, VERIFY_REG_A | VERIFY_REG_B_TYPE), // 0x1f
    op(0x20, "instance-of", 2, Format::K22c, IndexKind::TypeRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_TYPE), // 0x20
    op(0x21, "array-length", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x21
    op(0x22, "new-instance", 2, Format::K21c, IndexKind::TypeRef, VERIFY_REG_A | VERIFY_REG_B_NEW_INSTANCE), // 0x22
    op(0x23, "new-array", 2, Format::K22c, IndexKind::TypeRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_NEW_ARRAY), // 0x23
    op(0x24, "filled-new-array", 3, Format::K35c, IndexKind::TypeRef, VERIFY_REG_B_FILLED_NEW_ARRAY | VERIFY_VAR_ARG), // 0x24
    op(0x25, "filled-new-array/range", 3, Format::K3rc, IndexKind::TypeRef, VERIFY_REG_B_FILLED_NEW_ARRAY | VERIFY_VAR_ARG_RANGE), // 0x25
    op(0x26, "fill-array-data", 3, Format::K31t, IndexKind::None, VERIFY_REG_A | VERIFY_ARRAY_DATA), // 0x26
    op(0x27, "throw", 1, Format::K11x, IndexKind::None, VERIFY_REG_A), // 0x27
    op(0x28, "goto", 1, Format::K10t, IndexKind::None, VERIFY_BRANCH_TARGET), // 0x28
    op(0x29, "goto/16", 2, Format::K20t, IndexKind::None, VERIFY_BRANCH_TARGET), // 0x29
    op(0x2A, "goto/32", 3, Format::K30t, IndexKind::None, VERIFY_BRANCH_TARGET), // 0x2a
    op(0x2B, "packed-switch", 3, Format::K31t, IndexKind::None, VERIFY_REG_A | VERIFY_SWITCH_TARGETS), // 0x2b
    op(0x2C, "sparse-switch", 3, Format::K31t, IndexKind::None, VERIFY_REG_A | VERIFY_SWITCH_TARGETS), // 0x2c
    op(0x2D, "cmpl-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x2d
    op(0x2E, "cmpg-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x2e
    op(0x2F, "cmpl-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x2f
    op(0x30, "cmpg-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x30
    op(0x31, "cmp-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x31
    op(0x32, "if-eq", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x32
    op(0x33, "if-ne", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x33
    op(0x34, "if-lt", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x34
    op(0x35, "if-ge", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x35
    op(0x36, "if-gt", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x36
    op(0x37, "if-le", 2, Format::K22t, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_BRANCH_TARGET), // 0x37
    op(0x38, "if-eqz", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x38
    op(0x39, "if-nez", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x39
    op(0x3A, "if-ltz", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x3a
    op(0x3B, "if-gez", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x3b
    op(0x3C, "if-gtz", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x3c
    op(0x3D, "if-lez", 2, Format::K21t, IndexKind::None, VERIFY_REG_A | VERIFY_BRANCH_TARGET), // 0x3d
    None,                                                              // 0x3e
    None,                                                              // 0x3f
    None,                                                              // 0x40
    None,                                                              // 0x41
    None,                                                              // 0x42
    None,                                                              // 0x43
    op(0x44, "aget", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x44
    op(0x45, "aget-wide", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B | VERIFY_REG_C), // 0x45
    op(0x46, "aget-object", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x46
    op(0x47, "aget-boolean", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x47
    op(0x48, "aget-byte", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x48
    op(0x49, "aget-char", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x49
    op(0x4A, "aget-short", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x4a
    op(0x4B, "aput", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x4b
    op(0x4C, "aput-wide", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B | VERIFY_REG_C), // 0x4c
    op(0x4D, "aput-object", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x4d
    op(0x4E, "aput-boolean", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x4e
    op(0x4F, "aput-byte", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x4f
    op(0x50, "aput-char", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x50
    op(0x51, "aput-short", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x51
    op(0x52, "iget", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x52
    op(0x53, "iget-wide", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A_WIDE | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x53
    op(0x54, "iget-object", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x54
    op(0x55, "iget-boolean", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x55
    op(0x56, "iget-byte", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x56
    op(0x57, "iget-char", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x57
    op(0x58, "iget-short", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x58
    op(0x59, "iput", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x59
    op(0x5A, "iput-wide", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A_WIDE | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5a
    op(0x5B, "iput-object", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5b
    op(0x5C, "iput-boolean", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5c
    op(0x5D, "iput-byte", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5d
    op(0x5E, "iput-char", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5e
    op(0x5F, "iput-short", 2, Format::K22c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C_FIELD), // 0x5f
    op(0x60, "sget", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x60
    op(0x61, "sget-wide", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A_WIDE | VERIFY_REG_B_FIELD), // 0x61
    op(0x62, "sget-object", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x62
    op(0x63, "sget-boolean", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x63
    op(0x64, "sget-byte", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x64
    op(0x65, "sget-char", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x65
    op(0x66, "sget-short", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x66
    op(0x67, "sput", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x67
    op(0x68, "sput-wide", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A_WIDE | VERIFY_REG_B_FIELD), // 0x68
    op(0x69, "sput-object", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x69
    op(0x6A, "sput-boolean", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x6a
    op(0x6B, "sput-byte", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x6b
    op(0x6C, "sput-char", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x6c
    op(0x6D, "sput-short", 2, Format::K21c, IndexKind::FieldRef, VERIFY_REG_A | VERIFY_REG_B_FIELD), // 0x6d
    op(0x6E, "invoke-virtual", 3, Format::K35c, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_NON_ZERO), // 0x6e
    op(0x6F, "invoke-super", 3, Format::K35c, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_NON_ZERO), // 0x6f
    op(0x70, "invoke-direct", 3, Format::K35c, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_NON_ZERO), // 0x70
    op(0x71, "invoke-static", 3, Format::K35c, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG), // 0x71
    op(0x72, "invoke-interface", 3, Format::K35c, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_NON_ZERO), // 0x72
    None,                                                              // 0x73
    op(0x74, "invoke-virtual/range", 3, Format::K3rc, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE_NON_ZERO), // 0x74
    op(0x75, "invoke-super/range", 3, Format::K3rc, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE_NON_ZERO), // 0x75
    op(0x76, "invoke-direct/range", 3, Format::K3rc, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE_NON_ZERO), // 0x76
    op(0x77, "invoke-static/range", 3, Format::K3rc, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE), // 0x77
    op(0x78, "invoke-interface/range", 3, Format::K3rc, IndexKind::MethodRef, VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE_NON_ZERO), // 0x78
    None,                                                              // 0x79
    None,                                                              // 0x7a
    op(0x7B, "neg-int", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x7b
    op(0x7C, "not-int", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x7c
    op(0x7D, "neg-long", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x7d
    op(0x7E, "not-long", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x7e
    op(0x7F, "neg-float", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x7f
    op(0x80, "neg-double", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x80
    op(0x81, "int-to-long", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0x81
    op(0x82, "int-to-float", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x82
    op(0x83, "int-to-double", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0x83
    op(0x84, "long-to-int", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE), // 0x84
    op(0x85, "long-to-float", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE), // 0x85
    op(0x86, "long-to-double", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x86
    op(0x87, "float-to-int", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x87
    op(0x88, "float-to-long", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0x88
    op(0x89, "float-to-double", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0x89
    op(0x8A, "double-to-int", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE), // 0x8a
    op(0x8B, "double-to-long", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0x8b
    op(0x8C, "double-to-float", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B_WIDE), // 0x8c
    op(0x8D, "int-to-byte", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x8d
    op(0x8E, "int-to-char", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x8e
    op(0x8F, "int-to-short", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0x8f
    op(0x90, "add-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x90
    op(0x91, "sub-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x91
    op(0x92, "mul-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x92
    op(0x93, "div-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x93
    op(0x94, "rem-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x94
    op(0x95, "and-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x95
    op(0x96, "or-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x96
    op(0x97, "xor-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x97
    op(0x98, "shl-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x98
    op(0x99, "shr-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x99
    op(0x9A, "ushr-int", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0x9a
    op(0x9B, "add-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x9b
    op(0x9C, "sub-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x9c
    op(0x9D, "mul-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x9d
    op(0x9E, "div-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x9e
    op(0x9F, "rem-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0x9f
    op(0xA0, "and-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xa0
    op(0xA1, "or-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xa1
    op(0xA2, "xor-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xa2
    op(0xA3, "shl-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C), // 0xa3
    op(0xA4, "shr-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C), // 0xa4
    op(0xA5, "ushr-long", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C), // 0xa5
    op(0xA6, "add-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0xa6
    op(0xA7, "sub-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0xa7
    op(0xA8, "mul-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0xa8
    op(0xA9, "div-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0xa9
    op(0xAA, "rem-float", 2, Format::K23x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B | VERIFY_REG_C), // 0xaa
    op(0xAB, "add-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xab
    op(0xAC, "sub-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xac
    op(0xAD, "mul-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xad
    op(0xAE, "div-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xae
    op(0xAF, "rem-double", 2, Format::K23x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE | VERIFY_REG_C_WIDE), // 0xaf
    op(0xB0, "add-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb0
    op(0xB1, "sub-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb1
    op(0xB2, "mul-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb2
    op(0xB3, "div-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb3
    op(0xB4, "rem-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb4
    op(0xB5, "and-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb5
    op(0xB6, "or-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb6
    op(0xB7, "xor-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb7
    op(0xB8, "shl-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb8
    op(0xB9, "shr-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xb9
    op(0xBA, "ushr-int/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xba
    op(0xBB, "add-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xbb
    op(0xBC, "sub-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xbc
    op(0xBD, "mul-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xbd
    op(0xBE, "div-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xbe
    op(0xBF, "rem-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xbf
    op(0xC0, "and-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xc0
    op(0xC1, "or-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xc1
    op(0xC2, "xor-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xc2
    op(0xC3, "shl-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0xc3
    op(0xC4, "shr-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0xc4
    op(0xC5, "ushr-long/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B), // 0xc5
    op(0xC6, "add-float/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xc6
    op(0xC7, "sub-float/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xc7
    op(0xC8, "mul-float/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xc8
    op(0xC9, "div-float/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xc9
    op(0xCA, "rem-float/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xca
    op(0xCB, "add-double/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xcb
    op(0xCC, "sub-double/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xcc
    op(0xCD, "mul-double/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xcd
    op(0xCE, "div-double/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xce
    op(0xCF, "rem-double/2addr", 1, Format::K12x, IndexKind::None, VERIFY_REG_A_WIDE | VERIFY_REG_B_WIDE), // 0xcf
    op(0xD0, "add-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd0
    op(0xD1, "rsub-int", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd1
    op(0xD2, "mul-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd2
    op(0xD3, "div-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd3
    op(0xD4, "rem-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd4
    op(0xD5, "and-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd5
    op(0xD6, "or-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd6
    op(0xD7, "xor-int/lit16", 2, Format::K22s, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd7
    op(0xD8, "add-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd8
    op(0xD9, "rsub-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xd9
    op(0xDA, "mul-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xda
    op(0xDB, "div-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xdb
    op(0xDC, "rem-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xdc
    op(0xDD, "and-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xdd
    op(0xDE, "or-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xde
    op(0xDF, "xor-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xdf
    op(0xE0, "shl-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xe0
    op(0xE1, "shr-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xe1
    op(0xE2, "ushr-int/lit8", 2, Format::K22b, IndexKind::None, VERIFY_REG_A | VERIFY_REG_B), // 0xe2
    None,                                                              // 0xe3
    None,                                                              // 0xe4
    None,                                                              // 0xe5
    None,                                                              // 0xe6
    None,                                                              // 0xe7
    None,                                                              // 0xe8
    None,                                                              // 0xe9
    None,                                                              // 0xea
    None,                                                              // 0xeb
    None,                                                              // 0xec
    None,                                                              // 0xed
    None,                                                              // 0xee
    None,                                                              // 0xef
    None,                                                              // 0xf0
    None,                                                              // 0xf1
    None,                                                              // 0xf2
    None,                                                              // 0xf3
    None,                                                              // 0xf4
    None,                                                              // 0xf5
    None,                                                              // 0xf6
    None,                                                              // 0xf7
    None,                                                              // 0xf8
    None,                                                              // 0xf9
    op(
        0xFA,
        "invoke-polymorphic",
        4,
        Format::K45cc,
        IndexKind::MethodAndProtoRef,
        VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_NON_ZERO | VERIFY_REG_H_PROTOTYPE,
    ), // 0xfa
    op(
        0xFB,
        "invoke-polymorphic/range",
        4,
        Format::K4rcc,
        IndexKind::MethodAndProtoRef,
        VERIFY_REG_B_METHOD | VERIFY_VAR_ARG_RANGE_NON_ZERO | VERIFY_REG_H_PROTOTYPE,
    ), // 0xfb
    op(0xFC, "invoke-custom", 3, Format::K35c, IndexKind::CallSiteRef, VERIFY_REG_B_CALL_SITE | VERIFY_VAR_ARG), // 0xfc
    op(0xFD, "invoke-custom/range", 3, Format::K3rc, IndexKind::CallSiteRef, VERIFY_REG_B_CALL_SITE | VERIFY_VAR_ARG_RANGE), // 0xfd
    op(0xFE, "const-method-handle", 2, Format::K21c, IndexKind::MethodHandleRef, VERIFY_REG_A | VERIFY_REG_B_METHOD_HANDLE), // 0xfe
    op(0xFF, "const-method-type", 2, Format::K21c, IndexKind::ProtoRef, VERIFY_REG_A | VERIFY_REG_B_PROTOTYPE), // 0xff
];
