//! The names asc hands to decompiler backends (docs/decompile-backends.md
//! §6.2, §7): new names for classes, fields and methods, keyed in asc's
//! member notation, the one `findrefs` prints (`Lowner;->name:Type`,
//! `Lowner;->name(args)Ret`).
//!
//! Keys are always the names as they are in the DEX (obfuscated, if the
//! program is); values are the names to show instead, which come only from
//! a mapping file the user supplies (R8 / ProGuard `mapping.txt`, see
//! [`NameMappings::from_proguard`]). asc keeps no renames of its own and
//! derives no deobfuscation aliases; without a mapping file every name stays
//! as it is. Only decompiled source uses these names: query outputs
//! (`findrefs`, smali, …) keep the DEX's own descriptors.

use super::dalvik_types;
use crate::Engine;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Why a mapping entry was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MappingError {
    #[error("not a class descriptor: {0:?} (want Lpkg/Name;)")]
    Class(String),
    #[error("not a field signature: {0:?} (want Lowner;->name:Type)")]
    Field(String),
    #[error("not a method signature: {0:?} (want Lowner;->name(args)Ret)")]
    Method(String),
    #[error("not a usable new name: {0:?}")]
    NewName(String),
    #[error("not a usable new class name: {0:?} (want Lpkg/Name;)")]
    NewClass(String),
}

/// A field as `Lowner;->name:Type`. Every part borrows from the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct FieldRef<'a> {
    pub class: &'a str,
    pub name: &'a str,
    pub ty: &'a str,
}

impl<'a> FieldRef<'a> {
    /// Parse the canonical form exactly as written (no trimming, no other
    /// spellings), so `parse(s).to_string() == s`.
    pub fn parse(signature: &'a str) -> Result<FieldRef<'a>, MappingError> {
        let bad = || MappingError::Field(signature.to_string());
        let (class, member) = signature.split_once("->").ok_or_else(bad)?;
        let (name, ty) = member.split_once(':').ok_or_else(bad)?;
        let field_type = matches!(dalvik_types(ty).as_deref(), Some([t]) if *t != "V");
        (is_class_descriptor(class) && is_simple_name(name) && field_type).then_some(FieldRef { class, name, ty }).ok_or_else(bad)
    }
}

impl fmt::Display for FieldRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}:{}", self.class, self.name, self.ty)
    }
}

/// A method as `Lowner;->name(args)Ret`; `proto` is `(args)Ret`, which
/// tells overloads apart. Every part borrows from the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct MethodRef<'a> {
    pub class: &'a str,
    pub name: &'a str,
    pub proto: &'a str,
}

impl<'a> MethodRef<'a> {
    /// Parse the canonical form exactly as written, like [`FieldRef::parse`].
    pub fn parse(signature: &'a str) -> Result<MethodRef<'a>, MappingError> {
        let bad = || MappingError::Method(signature.to_string());
        let (class, member) = signature.split_once("->").ok_or_else(bad)?;
        let open = member.find('(').ok_or_else(bad)?;
        let (name, proto) = member.split_at(open);
        let (params, ret) = proto[1..].split_once(')').ok_or_else(bad)?;
        let name_ok = is_simple_name(name) || name == "<init>" || name == "<clinit>";
        let params_ok = params.is_empty() || dalvik_types(params).is_some_and(|ps| !ps.contains(&"V"));
        let ret_ok = matches!(dalvik_types(ret).as_deref(), Some([_]));
        (is_class_descriptor(class) && name_ok && params_ok && ret_ok).then_some(MethodRef { class, name, proto }).ok_or_else(bad)
    }
}

impl fmt::Display for MethodRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}{}", self.class, self.name, self.proto)
    }
}

/// `Lpkg/Name;`, `LName;`, `Lpkg/Outer$Inner;`: a class (not array or
/// primitive) descriptor whose path segments are simple names.
pub(super) fn is_class_descriptor(s: &str) -> bool {
    s.strip_prefix('L').and_then(|d| d.strip_suffix(';')).is_some_and(|inner| inner.split('/').all(is_simple_name))
}

/// A DEX simple name as far as the notation needs: non-empty and free of
/// the characters that delimit descriptors and signatures. Anything else
/// (`ۢۤܺ`, `-`, digits first) is the obfuscator's business and allowed.
fn is_simple_name(s: &str) -> bool {
    !s.is_empty() && !s.contains(['/', ';', '.', '[', '(', ')', ':', '<', '>'])
}

/// A new name must read as one identifier in any target language's output
/// once the backend has escaped it; the notation's delimiters, whitespace
/// and control characters never do.
fn is_new_name(s: &str) -> bool {
    is_simple_name(s) && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A new class name is a whole descriptor (the package may change too) whose
/// every segment is a usable new name; `$` (nesting) is just a character.
fn is_new_class(s: &str) -> bool {
    s.strip_prefix('L').and_then(|d| d.strip_suffix(';')).is_some_and(|inner| inner.split('/').all(is_new_name))
}

/// Resolves the names decompiled source shows, in process (the embedded
/// decompiler) or behind a protocol (external backends get [`NameMappings`]
/// as JSON). Keys are the names in the DEX (`Lz/c;`, `Lz/c;->a(I)V`);
/// `None` keeps the name the program has.
pub trait NameResolver {
    /// The full new descriptor of the class `descriptor`: `Lz/c;` →
    /// `Lcom/example/Cart;`. The package may differ from the DEX's; for a
    /// nested class the value is the whole binary name (`…/Cart$Line;`).
    fn class(&self, descriptor: &str) -> Option<&str>;
    /// The new name of the field `Lowner;->name:Type`.
    fn field(&self, signature: &str) -> Option<&str>;
    /// The new name of the method `Lowner;->name(args)Ret`.
    fn method(&self, signature: &str) -> Option<&str>;
}

/// The §6.2 `mappings` object: `classes` maps a descriptor to the class's
/// full new descriptor, `fields` and `methods` map a member signature to the
/// member's new simple name. Keys use the DEX's own names throughout, so a
/// member of a renamed class is still keyed by the old class descriptor. Keys are checked on insertion and
/// kept sorted, so iteration, serialisation and [`NameMappings::hash`] do
/// not depend on insertion order. The default (empty) value is the identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameMappings {
    classes: BTreeMap<String, String>,
    fields: BTreeMap<String, String>,
    methods: BTreeMap<String, String>,
}

/// SHA-256 of a [`NameMappings`]' contents, part of the decompile cache key
/// (§8). Equal mappings hash equally whatever order they were built in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappingsHash([u8; 32]);

impl MappingsHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hex.
impl fmt::Display for MappingsHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl NameMappings {
    pub fn new() -> NameMappings {
        NameMappings::default()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.fields.is_empty() && self.methods.is_empty()
    }

    /// Rename the class `descriptor` to the descriptor `new_descriptor`
    /// (`Lz/c;` → `Lcom/example/Cart;`); returns the name it replaced.
    pub fn insert_class(&mut self, descriptor: &str, new_descriptor: &str) -> Result<Option<String>, MappingError> {
        if !is_class_descriptor(descriptor) {
            return Err(MappingError::Class(descriptor.to_string()));
        }
        if !is_new_class(new_descriptor) {
            return Err(MappingError::NewClass(new_descriptor.to_string()));
        }
        Ok(self.classes.insert(descriptor.to_string(), new_descriptor.to_string()))
    }

    /// Rename the field `signature` (`Lowner;->name:Type`); returns the name
    /// it replaced.
    pub fn insert_field(&mut self, signature: &str, new_name: &str) -> Result<Option<String>, MappingError> {
        FieldRef::parse(signature)?;
        Ok(self.fields.insert(signature.to_string(), checked_new_name(new_name)?))
    }

    /// Rename the method `signature` (`Lowner;->name(args)Ret`); returns the
    /// name it replaced. Constructors and static initialisers keep their
    /// names, so `<init>` / `<clinit>` are refused.
    pub fn insert_method(&mut self, signature: &str, new_name: &str) -> Result<Option<String>, MappingError> {
        let method = MethodRef::parse(signature)?;
        if method.name.starts_with('<') {
            return Err(MappingError::Method(signature.to_string()));
        }
        Ok(self.methods.insert(signature.to_string(), checked_new_name(new_name)?))
    }

    /// Descriptor → new descriptor, sorted by the DEX's descriptor.
    pub fn classes(&self) -> &BTreeMap<String, String> {
        &self.classes
    }

    /// Field signature → new name, sorted by signature.
    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.fields
    }

    /// Method signature → new name, sorted by signature.
    pub fn methods(&self) -> &BTreeMap<String, String> {
        &self.methods
    }

    /// The entries a request needs: the classes `keep` accepts and the
    /// members they own. For a slice, `keep` should accept every class the
    /// slice refers to, not only its targets, since references to renamed
    /// classes and members are renamed in the output too.
    #[must_use]
    pub fn restricted_to(&self, keep: impl Fn(&str) -> bool) -> NameMappings {
        let owned_by_kept = |signature: &String| signature.split_once("->").is_some_and(|(class, _)| keep(class));
        let filter = |map: &BTreeMap<String, String>, keep_key: &dyn Fn(&String) -> bool| -> BTreeMap<String, String> {
            map.iter().filter(|(k, _)| keep_key(k)).map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        NameMappings {
            classes: filter(&self.classes, &|d| keep(d)),
            fields: filter(&self.fields, &owned_by_kept),
            methods: filter(&self.methods, &owned_by_kept),
        }
    }

    /// The stable hash of the entries: sections in a fixed order, each entry
    /// length-prefixed so no two different mappings feed the same bytes.
    pub fn hash(&self) -> MappingsHash {
        let mut h = Sha256::new();
        h.update(b"asc-name-mappings/2");
        for (tag, map) in [(b'c', &self.classes), (b'f', &self.fields), (b'm', &self.methods)] {
            h.update([tag]);
            h.update((map.len() as u64).to_le_bytes());
            for (k, v) in map {
                for s in [k, v] {
                    h.update((s.len() as u64).to_le_bytes());
                    h.update(s.as_bytes());
                }
            }
        }
        MappingsHash(h.finalize().into())
    }
}

fn checked_new_name(new_name: &str) -> Result<String, MappingError> {
    if is_new_name(new_name) { Ok(new_name.to_string()) } else { Err(MappingError::NewName(new_name.to_string())) }
}

impl NameResolver for NameMappings {
    fn class(&self, descriptor: &str) -> Option<&str> {
        self.classes.get(descriptor).map(String::as_str)
    }

    fn field(&self, signature: &str) -> Option<&str> {
        self.fields.get(signature).map(String::as_str)
    }

    fn method(&self, signature: &str) -> Option<&str> {
        self.methods.get(signature).map(String::as_str)
    }
}

impl Engine {
    /// Show the names of `mappings` in decompiled source (typically read
    /// from the user's `mapping.txt` with [`NameMappings::from_proguard_file`]).
    /// Shared, since one mapping file serves many engines.
    pub fn with_name_mappings(mut self, mappings: impl Into<Arc<NameMappings>>) -> Engine {
        self.name_mappings = mappings.into();
        self
    }

    /// The names this program's classes and members go by in decompiled
    /// output: the set given to [`Engine::with_name_mappings`], or the
    /// identity (empty) when there is none, in which case every class and
    /// member keeps its own name (backends still escape names their language
    /// cannot spell). Narrow it to a request with [`NameMappings::restricted_to`].
    pub fn name_mappings(&self) -> &NameMappings {
        &self.name_mappings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_round_trip_through_their_parts() {
        let fields = ["Lbin/mt/json/JSONObject;->a:I", "Ll/ۢۤܺ;->ۢ:[Ljava/lang/String;", "LA$B$1;->this$0:LA$B;", "LC;->-x:J"];
        for s in fields {
            assert_eq!(FieldRef::parse(s).unwrap().to_string(), s, "{s}");
        }
        let f = FieldRef::parse("Lpkg/Outer$Inner;->val$x:Lpkg/Outer;").unwrap();
        assert_eq!(f, FieldRef { class: "Lpkg/Outer$Inner;", name: "val$x", ty: "Lpkg/Outer;" });

        let methods = ["Lc;->run()V", "Lc;->run(I)V", "Lc;-><init>(ILjava/lang/String;[[B)V", "La/b$c;->ۢۤ(La/b;)La/b$c;"];
        for s in methods {
            assert_eq!(MethodRef::parse(s).unwrap().to_string(), s, "{s}");
        }
        let m = MethodRef::parse("Lpkg/Outer$1;->access$000(Lpkg/Outer;)I").unwrap();
        assert_eq!(m, MethodRef { class: "Lpkg/Outer$1;", name: "access$000", proto: "(Lpkg/Outer;)I" });
    }

    #[test]
    fn non_canonical_signatures_are_refused() {
        for s in ["Lc;->f", "Lc;->f:V", "Lc;->:I", "c->f:I", "[I->f:I", "Lc;->f:I ", " Lc;->f:I", "Lc;->f:Lx", "La//b;->f:I"] {
            assert_eq!(FieldRef::parse(s), Err(MappingError::Field(s.into())), "{s}");
        }
        for s in ["Lc;->run", "Lc;->run()", "Lc;->run(V)V", "Lc;->(I)V", "Lc;->run(I)VV", "Lc;->a.b()V", "com.a.B->run()V"] {
            assert_eq!(MethodRef::parse(s), Err(MappingError::Method(s.into())), "{s}");
        }
    }

    #[test]
    fn overloads_are_distinct_entries() {
        let mut m = NameMappings::new();
        m.insert_method("Lc;->a(I)V", "setCount").unwrap();
        m.insert_method("Lc;->a(Ljava/lang/String;)V", "setName").unwrap();
        m.insert_method("Lc;->a()I", "count").unwrap();
        assert_eq!(m.method("Lc;->a(I)V"), Some("setCount"));
        assert_eq!(m.method("Lc;->a(Ljava/lang/String;)V"), Some("setName"));
        assert_eq!(m.method("Lc;->a()I"), Some("count"));
        assert_eq!(m.method("Lc;->a(J)V"), None);
        // A field and a method of one name are separate too.
        m.insert_field("Lc;->a:I", "count").unwrap();
        assert_eq!((m.field("Lc;->a:I"), m.field("Lc;->a:J")), (Some("count"), None));
    }

    #[test]
    fn nested_classes_keep_their_descriptor() {
        let mut m = NameMappings::new();
        m.insert_class("Lbin/mt/json/JSONObject$Member;", "Lbin/mt/json/JSONObject$Entry;").unwrap();
        m.insert_class("Ll/ۢۤܺ;", "Lbin/mt/json/LinkedTable;").unwrap();
        assert_eq!(m.class("Lbin/mt/json/JSONObject$Member;"), Some("Lbin/mt/json/JSONObject$Entry;"));
        assert_eq!(m.class("Lbin/mt/json/JSONObject;"), None);
        // The package may change: mapping files name the original class in full.
        assert_eq!(m.class("Ll/ۢۤܺ;"), Some("Lbin/mt/json/LinkedTable;"));
    }

    #[test]
    fn bad_keys_and_names_are_refused() {
        let mut m = NameMappings::new();
        assert_eq!(m.insert_class("com.a.B", "LX;"), Err(MappingError::Class("com.a.B".into())));
        assert_eq!(m.insert_class("[La;", "LX;"), Err(MappingError::Class("[La;".into())));
        for bad in ["X", "com.a.X", "Lcom/a/X", "Lcom//X;", "L;", "Lcom/a b;", "[LX;", "I"] {
            assert_eq!(m.insert_class("La;", bad), Err(MappingError::NewClass(bad.into())), "{bad:?}");
        }
        assert_eq!(m.insert_method("Lc;-><init>()V", "make"), Err(MappingError::Method("Lc;-><init>()V".into())));
        for bad in ["", "a b", "a.b", "La;", "x\n"] {
            assert_eq!(m.insert_field("Lc;->f:I", bad), Err(MappingError::NewName(bad.into())), "{bad:?}");
        }
        assert!(m.is_empty());
        assert_eq!(m.insert_class("La;", "Lp/X;"), Ok(None));
        assert_eq!(m.insert_class("La;", "Lq/Y$Z;"), Ok(Some("Lp/X;".into())));
    }

    fn sample(order: &[usize]) -> NameMappings {
        let entries: [(&str, &str); 6] = [
            ("c:Lb;", "Lcom/x/Bee;"),
            ("c:La$1;", "Lcom/x/Aye$1;"),
            ("f:Lb;->x:I", "size"),
            ("f:La;->x:I", "count"),
            ("m:La;->x(I)V", "put"),
            ("m:La;->x()V", "clear"),
        ];
        let mut m = NameMappings::new();
        for &i in order {
            let (key, new) = entries[i];
            match key.split_at(2) {
                ("c:", d) => m.insert_class(d, new),
                ("f:", s) => m.insert_field(s, new),
                (_, s) => m.insert_method(s, new),
            }
            .unwrap();
        }
        m
    }

    #[test]
    fn order_and_hash_do_not_depend_on_insertion() {
        let (a, b) = (sample(&[0, 1, 2, 3, 4, 5]), sample(&[5, 3, 1, 4, 0, 2]));
        assert_eq!(a, b);
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.classes().keys().collect::<Vec<_>>(), ["La$1;", "Lb;"]);
        assert_eq!(a.fields().keys().collect::<Vec<_>>(), ["La;->x:I", "Lb;->x:I"]);
        assert_eq!(a.methods().keys().collect::<Vec<_>>(), ["La;->x()V", "La;->x(I)V"]);
    }

    #[test]
    fn hash_is_pinned_and_tells_contents_apart() {
        // Pinned: the hash is part of on-disk cache keys, so changing the
        // encoding must be deliberate (bump the `asc-name-mappings/N` tag).
        assert_eq!(NameMappings::new().hash().to_string(), "eb2a94d4e5862de88b4a5b6162d60ce874a1b831bf01c074921ec976becdad4e");
        assert_eq!(sample(&[0, 1, 2, 3, 4, 5]).hash().to_string(), "6eb831a95f17919d15479902c0e6f8d04471980d53733d9be3650064ef0cea5c");
        // The same strings in another section, or split differently, differ.
        let mut class = NameMappings::new();
        class.insert_class("La;", "Lab;").unwrap();
        let mut other = NameMappings::new();
        other.insert_class("La;", "La;").unwrap();
        assert_ne!(class.hash(), other.hash());
        let mut field = NameMappings::new();
        field.insert_field("La;->f:I", "x").unwrap();
        let mut method = NameMappings::new();
        method.insert_method("La;->f()I", "x").unwrap();
        assert_ne!(field.hash(), method.hash());
        assert_ne!(field.hash(), NameMappings::new().hash());
    }

    #[test]
    fn restriction_keeps_the_classes_and_their_members() {
        let m = sample(&[0, 1, 2, 3, 4, 5]);
        let only_a = m.restricted_to(|c| c.starts_with("La"));
        assert_eq!(only_a.classes().keys().collect::<Vec<_>>(), ["La$1;"]);
        assert_eq!(only_a.fields().keys().collect::<Vec<_>>(), ["La;->x:I"]);
        assert_eq!(only_a.methods().len(), 2);
        assert!(m.restricted_to(|_| false).is_empty());
        assert_eq!(m.restricted_to(|_| true), m);
    }

    #[test]
    fn engine_mappings_are_the_identity_unless_supplied() {
        let engine = Engine::new("unused.apk");
        assert!(engine.name_mappings().is_empty());
        assert_eq!(engine.name_mappings().class("La;"), None);
        let supplied = Arc::new(sample(&[0, 1, 2, 3, 4, 5]));
        let engine = Engine::new("unused.apk").with_name_mappings(Arc::clone(&supplied));
        assert_eq!(engine.name_mappings(), &*supplied);
        assert_eq!(engine.name_mappings().class("Lb;"), Some("Lcom/x/Bee;"));
    }
}
