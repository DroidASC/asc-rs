//! What the DEX and HarmonyOS engines of asc-rs read alike.
//!
//! [`rule`]: the syntax of a rule (`string:a & !method:{literal:b}`): where
//! parts start and end, sets in braces, files of a set, the nesting limit,
//! errors with their column. Which kinds there are and what each value
//! means is each engine's ([`rule::Grammar`]).

pub mod rule;
