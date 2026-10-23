//! The archives a path given to [`Apk::open`](crate::Apk::open) names: one
//! file, a directory of them, or several of either joined with `,`.

use crate::{ApkError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// File extensions a directory contributes.
const EXTENSIONS: [&str; 4] = ["apk", "jar", "zip", "dex"];
/// Directory levels a walk descends.
const MAX_DEPTH: usize = 8;

/// One archive of a program and the name its entries are prefixed with.
pub(crate) struct Source {
    pub path: PathBuf,
    pub label: String,
}

/// Which files an [`Apk`](crate::Apk) was opened from, with their sizes
/// and modification times ([`Apk::version_of`](crate::Apk::version_of)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(Vec<(PathBuf, u64, Option<SystemTime>)>);

impl Version {
    pub(crate) fn of_sources(sources: &[Source]) -> Result<Version> {
        let stat = |s: &Source| {
            let meta = fs::metadata(&s.path).map_err(|source| ApkError::Io { path: s.path.clone(), source })?;
            Ok((s.path.clone(), meta.len(), meta.modified().ok()))
        };
        Ok(Version(sources.iter().map(stat).collect::<Result<_>>()?))
    }
}

/// The paths `spec` joins with `,`, or `spec` itself when a file of that
/// name exists (or it has no comma).
fn parts(spec: &Path) -> Vec<PathBuf> {
    match spec.to_str() {
        Some(s) if s.contains(',') && !spec.exists() => s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(PathBuf::from).collect(),
        _ => vec![spec.to_path_buf()],
    }
}

/// See [`Apk::resolve`](crate::Apk::resolve).
pub(crate) fn resolve(spec: &Path, base: &Path) -> PathBuf {
    let parts = parts(&base.join(spec));
    if let [one] = &parts[..] {
        return one.clone();
    }
    let joined: Vec<String> = parts.iter().map(|p| base.join(p).to_string_lossy().into_owned()).collect();
    PathBuf::from(joined.join(","))
}

/// The archives `spec` names, in order: a lone file as it is (unlabelled);
/// directories walked in path order, their files labelled by their path
/// below the directory (and the directory's own name when `spec` lists
/// several paths); listed files by their file name. Labels are unique, a
/// file listed twice is kept once.
pub(crate) fn sources(spec: &Path) -> Result<Vec<Source>> {
    let parts = parts(spec);
    let several = parts.len() > 1;
    let mut out = Vec::new();
    for part in parts {
        let io = |source| ApkError::Io { path: part.clone(), source };
        if !fs::metadata(&part).map_err(io)?.is_dir() {
            let label = if several { name_of(&part) } else { String::new() };
            out.push(Source { path: part, label });
            continue;
        }
        let mut files = Vec::new();
        walk(&part, MAX_DEPTH, &mut files).map_err(io)?;
        files.sort();
        let top = if several { Some(name_of(&part)) } else { None };
        for path in files {
            let below = path.strip_prefix(&part).unwrap_or(&path);
            let rel = below.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
            let label = top.as_ref().map_or_else(|| rel.clone(), |t| format!("{t}/{rel}"));
            out.push(Source { path, label });
        }
    }
    let mut seen_paths = HashSet::new();
    out.retain(|s| seen_paths.insert(fs::canonicalize(&s.path).unwrap_or_else(|_| s.path.clone())));
    let mut seen_labels = HashSet::new();
    for s in &mut out {
        let base = s.label.clone();
        let mut n = 1;
        while !seen_labels.insert(s.label.clone()) {
            n += 1;
            s.label = format!("{base}#{n}");
        }
    }
    if out.is_empty() {
        return Err(ApkError::NoCode { path: spec.to_path_buf(), notes: vec!["no *.apk, *.jar, *.zip or *.dex in it".into()] });
    }
    Ok(out)
}

fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |n| n.to_string_lossy().into_owned())
}

/// Files of `dir` with one of [`EXTENSIONS`], `depth` levels down.
fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        // Follows links: a pulled system image often links its partitions.
        let Ok(meta) = fs::metadata(&path) else { continue };
        if meta.is_dir() {
            if depth > 0 {
                walk(&path, depth - 1, out)?;
            }
        } else if path.extension().and_then(|e| e.to_str()).is_some_and(|e| EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x))) {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_split_on_commas_unless_the_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join("a,b.apk");
        fs::write(&odd, b"x").unwrap();
        assert_eq!(parts(&odd), std::slice::from_ref(&odd));
        assert_eq!(parts(Path::new("x.jar, y.jar,")), [PathBuf::from("x.jar"), PathBuf::from("y.jar")]);
        assert_eq!(parts(Path::new("x.jar")), [PathBuf::from("x.jar")]);
        let base = Path::new("/work");
        assert_eq!(resolve(Path::new("x.jar,/abs/y.jar"), base), PathBuf::from("/work/x.jar,/abs/y.jar"));
        assert_eq!(resolve(Path::new("x.jar"), base), PathBuf::from("/work/x.jar"));
        assert_eq!(resolve(Path::new("/abs/x.jar"), base), PathBuf::from("/abs/x.jar"));
    }

    #[test]
    fn directories_are_walked_and_labelled() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("framework");
        fs::create_dir_all(root.join("oat/arm64")).unwrap();
        fs::create_dir_all(root.join("app/Tele")).unwrap();
        for f in ["services.jar", "framework.jar", "oat/arm64/services.odex", "app/Tele/Tele.apk", "notes.txt"] {
            fs::write(root.join(f), b"x").unwrap();
        }
        let labels = |spec: &Path| sources(spec).unwrap().into_iter().map(|s| s.label).collect::<Vec<_>>();
        assert_eq!(labels(&root), ["app/Tele/Tele.apk", "framework.jar", "services.jar"]);
        let lone = root.join("services.jar");
        assert_eq!(labels(&lone), [""]);
        // Listed with others: the directory's name leads, duplicates go.
        let spec = format!("{},{}", root.display(), lone.display());
        assert_eq!(labels(Path::new(&spec)), ["framework/app/Tele/Tele.apk", "framework/framework.jar", "framework/services.jar"]);
        let other = dir.path().join("other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("services.jar"), b"y").unwrap();
        let spec = format!("{},{}", lone.display(), other.join("services.jar").display());
        assert_eq!(labels(Path::new(&spec)), ["services.jar", "services.jar#2"]);
        assert!(matches!(sources(&other.join("missing.jar")), Err(ApkError::Io { .. })));
        let empty = dir.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(matches!(sources(&empty), Err(ApkError::NoCode { .. })));
    }
}
