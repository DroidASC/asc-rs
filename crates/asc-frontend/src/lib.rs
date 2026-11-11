//! The layer the `asc` command and the MCP server share above the engines,
//! so that both read a request and show an answer the same way.
//!
//! * [`format`](mod@format): which engine answers for a program (DEX or HarmonyOS).
//! * [`findrefs`]: the arguments of a DEX search as a query.
//! * [`harmony`]: HarmonyOS function spellings, name patterns, call trees
//!   as rows and the hints of an empty answer.
//! * [`class_text`]: smali split into methods, for picking and outlining.
//! * [`spill`]: the directory output too long for its reader goes to.
//!
//! What only one front end has stays there: command-line parsing and the
//! daemon in asc-cli, the protocol, argument leniency and reply budgets in
//! asc-mcp.

pub mod class_text;
pub mod findrefs;
pub mod format;
pub mod harmony;
pub mod spill;
