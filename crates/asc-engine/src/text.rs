//! The text form shared by every tool: one record per line, `|` between
//! columns, strings quoted and escaped ([`asc_query::text`]).

pub use asc_query::text::{quoted, value};
