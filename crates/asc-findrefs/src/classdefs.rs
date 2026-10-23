//! Subclass / implementor lookup straight from the `class_def_item` table
//! (Python `ClassDefItemScan`).
//!
//! Unlike the other queries this never touches code: the target descriptor is
//! resolved to its type index with a binary search over `type_ids`, then every
//! class definition's `superclass_idx` (or `interfaces` list) is compared with
//! it.

use crate::{ClassRelation, Result};
use asc_dex::{ClassDef, Dex};

/// `class_idx` of every class definition that extends / implements the class
/// whose MUTF-8 descriptor is `descriptor`, in `class_defs` order. A target
/// the DEX does not reference yields nothing.
///
/// The Python version finds superclass matches with a regex over the packed
/// table; comparing the field directly gives the same rows without its
/// non-overlapping-match blind spot.
pub(crate) fn related_classes(dex: &Dex<'_>, relation: ClassRelation, descriptor: &[u8]) -> Result<Vec<u32>> {
    let Some(target) = dex.find_type_idx(descriptor)? else { return Ok(Vec::new()) };
    let buf = dex.buf();
    let mut out = Vec::new();
    for i in 0..dex.class_def_count() {
        let off = dex.class_def_off(i);
        let hit = match relation {
            ClassRelation::Extends => asc_dex::read_u32(buf, off + 8)? == target,
            ClassRelation::Implements => {
                let interfaces_off = asc_dex::read_u32(buf, off + 12)?;
                // A type list holds u16 indexes: a target above that cannot be in one.
                interfaces_off != 0 && target <= u16::MAX as u32 && dex.type_list(interfaces_off)?.contains(&(target as u16))
            }
        };
        if hit {
            out.push(ClassDef::parse(buf, off)?.class_idx);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_fixture::{make_dex, make_rich_dex};

    fn names(dex: &Dex<'_>, idxs: Vec<u32>) -> Vec<String> {
        idxs.into_iter().map(|t| dex.type_descriptor(t).unwrap()).collect()
    }

    #[test]
    fn extends_and_implements_follow_class_def_order() {
        let data = make_rich_dex();
        let dex = Dex::parse(&data).unwrap();
        let ext = related_classes(&dex, ClassRelation::Extends, b"Ljava/lang/Object;").unwrap();
        let order: Vec<String> = dex.class_defs().map(|d| dex.type_descriptor(d.unwrap().class_idx).unwrap()).collect();
        assert_eq!(names(&dex, ext), order);
        let imp = related_classes(&dex, ClassRelation::Implements, b"Lexample/Iface;").unwrap();
        assert_eq!(names(&dex, imp), ["Lexample/Rich;"]);
        // Not transitive and not crossed: nobody extends the interface, nobody
        // implements Object, and a type with no definitions has no subclasses.
        assert!(related_classes(&dex, ClassRelation::Extends, b"Lexample/Iface;").unwrap().is_empty());
        assert!(related_classes(&dex, ClassRelation::Implements, b"Ljava/lang/Object;").unwrap().is_empty());
        assert!(related_classes(&dex, ClassRelation::Extends, b"Lexample/Missing;").unwrap().is_empty());
    }

    #[test]
    fn root_class_without_superclass_is_never_a_subclass() {
        // Lexample/Test; extends Object; Object itself is only referenced.
        let data = make_dex();
        let dex = Dex::parse(&data).unwrap();
        assert_eq!(names(&dex, related_classes(&dex, ClassRelation::Extends, b"Ljava/lang/Object;").unwrap()), ["Lexample/Test;"]);
        assert!(related_classes(&dex, ClassRelation::Extends, b"Lexample/Test;").unwrap().is_empty());
    }

    #[test]
    fn broken_interface_list_is_an_error() {
        let mut data = make_rich_dex();
        let dex = Dex::parse(&data).unwrap();
        let i = dex.class_defs().position(|d| d.unwrap().interfaces_off != 0).unwrap();
        let off = dex.class_def_off(i as u32) + 12;
        data[off..off + 4].copy_from_slice(&(u32::MAX - 8).to_le_bytes());
        let dex = Dex::parse(&data).unwrap();
        assert!(related_classes(&dex, ClassRelation::Implements, b"Lexample/Iface;").is_err());
        // Extends never reads the list.
        assert!(!related_classes(&dex, ClassRelation::Extends, b"Ljava/lang/Object;").unwrap().is_empty());
    }
}
