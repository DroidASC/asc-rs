//! `resources` on a HarmonyOS program: the arguments of the DEX tool carry
//! over. `query` / `search` read `resources.index` of each package; `xml`
//! prints a text file of a package as it is (the page list and route table
//! `module.json` names by `$profile:NAME`), where the DEX tool decodes a
//! binary XML file.

use super::Session;
use crate::{bool_arg, choice_arg, str_arg, usize_arg, Call, ToolError, ToolResult};
use asc_ark_engine::{EngineError, Pattern, ResourceField, ResourceRow, ResourceTables};
use serde_json::{json, Value};

/// Rows of a resource search or lookup, as on the DEX side.
const LIMIT: usize = 200;

/// What the tool takes on a HarmonyOS program, for the program's introduction.
pub(super) const USAGE: &str =
    "# resources: resources.index rows `0x01000000 string/app_name [base] \"value\"` (`PACKAGE | ` ahead in a program of several \
     packages): query=ID (0x01000000 or decimal) or NAME (string/app_name, $string:app_name, app.string.app_name), resolve=true \
     follows `$type:id` values; search=REGEX in=name|value|any; xml=\"$profile:main_pages\" (or a path inside the package) prints \
     that text file: page lists, route tables. Code holds a resource as its id (findrefs kind=number) or as the string \
     `app.type.name`; getclass names the ids (`# string/app_name \"value\"`)\n";

/// What a query that names no resource of the program says.
fn no_resource(error: EngineError) -> ToolError {
    match &error {
        EngineError::NotFound { what: "resource", .. } => ToolError(format!("{error}; `search` finds resources by name or value")),
        _ => error.into(),
    }
}

fn field_arg(args: &Value) -> Result<ResourceField, ToolError> {
    const CHOICES: &[(&str, &[&str])] = &[("name", &["key"]), ("value", &[]), ("any", &["both", "all"])];
    Ok(match choice_arg(args, "in", "any", CHOICES)? {
        "name" => ResourceField::Name,
        "value" => ResourceField::Value,
        _ => ResourceField::Any,
    })
}

/// What a `query` / `search` call answers: its rows, how many there are in
/// all, and the reference chains of `resolve`.
struct Answer {
    rows: Vec<ResourceRow>,
    total: usize,
    /// One line per package that has the resource.
    chains: Vec<String>,
}

fn answer(tables: &ResourceTables<'_>, args: &Value, limit: usize) -> Result<Answer, ToolError> {
    let several = tables.has_several_packages();
    if let Some(text) = str_arg(args, "search")? {
        let pattern = if bool_arg(args, "literal")?.unwrap_or(false) { Pattern::contains(text) } else { Pattern::regex(text)? };
        let (rows, total) = tables.search(&pattern, field_arg(args)?, limit);
        return Ok(Answer { rows, total, chains: Vec::new() });
    }
    let Some(query) = str_arg(args, "query")? else {
        return Err(ToolError("resources needs `query` (an id or type/name), `search` or `xml`".into()));
    };
    if bool_arg(args, "resolve")?.unwrap_or(false) {
        let resolved = tables.resolve(query).map_err(no_resource)?;
        let chains = resolved.iter().map(|resolved| resolved.chain_line(several)).collect();
        let rows: Vec<ResourceRow> = resolved.into_iter().map(|resolved| resolved.row).collect();
        return Ok(Answer { total: rows.len(), rows, chains });
    }
    let rows = tables.lookup(query).map_err(no_resource)?;
    let total = rows.len();
    Ok(Answer { rows: rows.into_iter().take(limit).collect(), total, chains: Vec::new() })
}

/// The text files `xml` names, one after the other; each under a
/// `# PACKAGE/PATH` line in a program of several packages.
fn files(session: &Session, target: &str) -> ToolResult {
    let engine = &session.engine;
    let files = engine.package_files(target).map_err(|error| match &error {
        EngineError::NotFound { what: "file", .. } => ToolError(format!(
            "{error} (give a path inside the package, e.g. resources/base/profile/main_pages.json, or a file resource: $profile:main_pages)"
        )),
        _ => no_resource(error),
    })?;
    let several = engine.has_several_packages();
    let mut text = String::new();
    for file in &files {
        if several {
            text.push_str(&format!("# {}/{}\n", file.package, file.path));
        }
        text.push_str(&file.text);
        if !file.text.ends_with('\n') {
            text.push('\n');
        }
    }
    let listed: Vec<Value> = files.iter().map(|file| json!({"package": file.package, "path": file.path, "text": file.text})).collect();
    let structured = json!({"apk_id": session.id, "path": target, "xml": text, "files": listed});
    Ok((text, structured))
}

/// Resource rows, or the text of a file.
pub(super) fn resources(session: &Session, args: &Value, _: &Call) -> ToolResult {
    if let Some(target) = str_arg(args, "xml")? {
        return files(session, target);
    }
    let limit = usize_arg(args, "limit")?.unwrap_or(LIMIT).max(1);
    let tables = session.engine.resources()?;
    let several = tables.has_several_packages();
    let Answer { rows, total, chains } = answer(&tables, args, limit)?;
    let mut text = String::new();
    // A chain goes ahead of the row it ends at.
    let mut chain_lines = chains.iter();
    for row in &rows {
        if let Some(chain) = chain_lines.next() {
            text.push_str(chain);
            text.push('\n');
        }
        text.push_str(&row.line(several));
        text.push('\n');
    }
    if total > rows.len() {
        text.push_str(&format!("# {} of {total} rows; raise `limit` for more\n", rows.len()));
    } else {
        text.push_str(&format!("# {total} rows\n"));
    }
    for note in tables.notes() {
        text.push_str(&format!("# warning: {note}\n"));
    }
    let structured = json!({
        "apk_id": session.id,
        "total": total,
        "rows": rows.iter().map(ResourceRow::json).collect::<Vec<_>>(),
        "chain": chains,
        "notes": tables.notes(),
    });
    Ok((text, structured))
}
