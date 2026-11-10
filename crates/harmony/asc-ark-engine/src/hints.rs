//! What to try after a search without results: the same text looked for as
//! another kind. Each hint costs one more search, so they are computed only
//! on request, for a query that found nothing.

use std::sync::atomic::AtomicBool;

use regex::Regex;

use crate::{Engine, Pattern, Query};

/// A regex or plain text as it is written on a command line.
fn shown(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Regex(regex) => regex.as_str().to_owned(),
        Pattern::Contains(text) => text.clone(),
        Pattern::Exact(name) => format!("={name}"),
    }
}

fn times(count: usize) -> String {
    if count == 1 {
        "once".to_owned()
    } else {
        format!("{count} times")
    }
}

impl Engine {
    fn count(&self, query: &Query, cancel: &AtomicBool) -> usize {
        // A hint is best effort: a search that fails has none.
        self.find_refs(query, cancel, &mut |_| {}).map_or(0, |summary| summary.total_results)
    }

    /// Suggestions for `query`, which found nothing: where else the program
    /// has what it names. Empty when there is nothing to suggest.
    pub fn no_results_hints(&self, query: &Query, cancel: &AtomicBool) -> Vec<String> {
        let mut hints = Vec::new();
        let string_pattern = |regex: &Regex| Pattern::Regex(regex.clone());
        match query {
            Query::StringRegex(_) | Query::StringLiteral(_) => {
                let pattern = match query {
                    Query::StringRegex(regex) => string_pattern(regex),
                    Query::StringLiteral(text) => Pattern::contains(text.as_str()),
                    _ => return hints,
                };
                // A module request is named by the module record, not by a string operand.
                let requests = self.module_requests(Some(&pattern)).unwrap_or_default();
                if let Some(first) = requests.first() {
                    hints.push(format!(
                        "{} module request{} match{} (e.g. {}): imports are not string operands, try `findrefs import`",
                        requests.len(),
                        if requests.len() == 1 { "" } else { "s" },
                        if requests.len() == 1 { "es" } else { "" },
                        first.request
                    ));
                }
            }
            Query::Prop { name, access } => {
                let unfiltered = access.map_or(0, |_| self.count(&Query::Prop { name: name.clone(), access: None }, cancel));
                if unfiltered > 0 {
                    // The name is right; only the filter is in the way.
                    return vec![format!("the property is accessed {} in other ways: drop --access", times(unfiltered))];
                }
                let global = self.count(&Query::Global { name: name.clone(), access: None }, cancel);
                if global > 0 {
                    hints.push(format!("{} is a global name, used {}: try `findrefs global`", shown(name), times(global)));
                }
                let defined = self.count(&Query::Method { record: None, name: name.clone() }, cancel);
                if defined > 0 {
                    hints.push(format!("{} names a function, defined {}: try `findrefs method`", shown(name), times(defined)));
                }
            }
            Query::Global { name, access } => {
                let unfiltered = access.map_or(0, |_| self.count(&Query::Global { name: name.clone(), access: None }, cancel));
                if unfiltered > 0 {
                    return vec![format!("the global is accessed {} in other ways: drop --access", times(unfiltered))];
                }
                let property = self.count(&Query::Prop { name: name.clone(), access: None }, cancel);
                if property > 0 {
                    hints.push(format!("{} is a property name, used {}: try `findrefs prop`", shown(name), times(property)));
                }
            }
            Query::Method { name, .. } => {
                let property = self.count(&Query::Prop { name: name.clone(), access: None }, cancel);
                if property > 0 {
                    hints.push(format!(
                        "no function is defined under that name, but it is a property name, used {}: try `findrefs prop` (--access call for its calls)",
                        times(property)
                    ));
                }
                if matches!(name, Pattern::Regex(regex) if regex.as_str().contains(['#', '^', '*'])) {
                    hints.push("a raw function name holds regex metacharacters (`*`, `^`): pass it with --exact".to_owned());
                }
            }
            Query::Import { .. } => hints.push("`findrefs import . --requests` lists the module requests of the program".to_owned()),
            Query::Call(_) => hints.push(
                "a call is matched by its callee path (import:REQUEST#NAME.member, global:NAME.member, this.member, local:FUNCTION, this@FUNCTION.member, argN@FUNCTION, lex(L,S), argN, callee().member, ?): `findrefs call .` lists them all"
                    .to_owned(),
            ),
            Query::Number(_) | Query::All(_) | Query::Not(_) | Query::CallTo(_) => {}
        }
        hints
    }
}
