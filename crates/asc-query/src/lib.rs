//! What the DEX and HarmonyOS engines of asc-rs read and write alike.
//!
//! * [`rule`]: the syntax of a rule (`string:a & !method:{literal:b}`):
//!   where parts start and end, sets in braces, files of a set, the nesting
//!   limit, errors with their column. Which kinds there are and what each
//!   value means is each engine's ([`rule::Grammar`]).
//! * [`text`]: one record per line, strings in JSON quotes, with everything
//!   that could break a line or disguise its content escaped.

pub mod rule;
pub mod text;
