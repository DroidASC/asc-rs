//! Dumps the `resources.index` of a `.hap` / `.hsp`, of the haps inside an
//! `.app`, or a bare index file: one line per value on stdout, a summary
//! per index on stderr.
//!
//! ```text
//! cargo run -p asc-hap --release --example resindex -- entry.hap
//! ```

use std::collections::BTreeMap;
use std::error::Error;
use std::io::{Cursor, Read, Write};
use std::time::Instant;

use asc_hap::ResourceIndex;
use zip::ZipArchive;

const INDEX: &str = "resources.index";

/// The indexes a file holds, each with the name to report it under.
fn indexes(label: &str, bytes: Vec<u8>, found: &mut Vec<(String, Vec<u8>)>) -> Result<(), Box<dyn Error>> {
    let Ok(mut zip) = ZipArchive::new(Cursor::new(&bytes)) else {
        found.push((label.to_owned(), bytes));
        return Ok(());
    };
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_owned();
        let nested = name.ends_with(".hap") || name.ends_with(".hsp");
        if name != INDEX && !nested {
            continue;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        let label = format!("{label}!{name}");
        if nested { indexes(&label, data, found)? } else { found.push((label, data)) }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut found = Vec::new();
    for path in std::env::args().skip(1) {
        indexes(&path, std::fs::read(&path)?, &mut found)?;
    }
    let mut out = std::io::stdout().lock();
    for (label, bytes) in &found {
        let start = Instant::now();
        let index = ResourceIndex::parse(bytes)?;
        let parsed = start.elapsed();
        let mut types = BTreeMap::new();
        let mut ids = 0;
        let mut last = None;
        for resource in &index {
            *types.entry(resource.kind().to_string()).or_insert(0usize) += 1;
            ids += usize::from(last.replace(resource.id()) != Some(resource.id()));
            writeln!(out, "{resource}")?;
        }
        let qualifiers: Vec<String> = index.qualifiers().iter().map(ToString::to_string).collect();
        eprintln!(
            "# {label}: {:?} {:?}, {} bytes, {ids} resources, {} values, parsed in {parsed:?}\n#   types {types:?}\n#   qualifiers {qualifiers:?}",
            index.format(),
            index.version(),
            bytes.len(),
            index.len(),
        );
    }
    Ok(())
}
