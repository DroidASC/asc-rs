#!/usr/bin/env python3
"""Generate `src/attrs.rs` (the `android:attr` resource-id -> name table) from the
Android SDK's `public-final.xml`.

Usage:
    python3 gen/gen_attrs.py [PUBLIC_FINAL_XML] [OUTPUT_RS]

Defaults:
    PUBLIC_FINAL_XML = $ANDROID_HOME (or ~/Android/Sdk) / platforms/<newest android-*>/data/res/values/public-final.xml
    OUTPUT_RS        = <this crate>/src/attrs.rs
"""

import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.dirname(HERE)


def default_public_final():
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or os.path.expanduser("~/Android/Sdk")
    candidates = glob.glob(os.path.join(sdk, "platforms", "android-*", "data", "res", "values", "public-final.xml"))
    if not candidates:
        sys.exit(f"no public-final.xml found under {sdk}/platforms; pass the path explicitly")

    def level(p):
        m = re.search(r"android-(\d+)(?:\.(\d+))?", p)
        return (int(m.group(1)), int(m.group(2) or 0)) if m else (0, 0)

    return max(candidates, key=level)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else default_public_final()
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(CRATE, "src", "attrs.rs")

    table = {}
    for e in ET.parse(src).iter("public"):
        if e.get("type") != "attr" or e.get("id") is None:
            continue
        name = e.get("name")
        rid = int(e.get("id"), 16)
        if rid >> 24 != 0x01:
            sys.exit(f"unexpected non-framework attr id {rid:#010x} ({name})")
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            sys.exit(f"unexpected attr name {name!r}")
        if rid in table and table[rid] != name:
            sys.exit(f"duplicate id {rid:#010x}: {table[rid]} vs {name}")
        table[rid] = name

    entries = sorted(table.items())
    # Display the source path relative to the SDK root when possible, so the header is stable across machines.
    shown_src = src
    m = re.search(r"(platforms[/\\]android-[^/\\]+[/\\].*)$", src)
    if m:
        shown_src = "$ANDROID_HOME/" + m.group(1).replace("\\", "/")

    out = []
    out.append("//! Names of `android:` attribute resource ids (`0x0101xxxx`), used to repair")
    out.append("//! manifests whose attribute names were stripped or obfuscated in the string pool.")
    out.append("//!")
    out.append("//! THIS FILE IS GENERATED - DO NOT EDIT BY HAND.")
    out.append("//!")
    out.append(f"//! Source: `{shown_src}`")
    out.append(f"//! Entries: {len(entries)}")
    out.append("//!")
    out.append("//! Regenerate with:")
    out.append("//!")
    out.append("//! ```text")
    out.append("//! python3 crates/asc-axml/gen/gen_attrs.py [path/to/public-final.xml] [crates/asc-axml/src/attrs.rs]")
    out.append("//! ```")
    out.append("")
    out.append("/// Look up the `android:attr` name for a framework attribute resource id.")
    out.append("pub fn android_attr_name(id: u32) -> Option<&'static str> {")
    out.append("    ANDROID_ATTRS.binary_search_by_key(&id, |&(rid, _)| rid).ok().map(|i| ANDROID_ATTRS[i].1)")
    out.append("}")
    out.append("")
    out.append("/// `(resource id, name)` pairs sorted by resource id.")
    out.append("#[rustfmt::skip]")
    out.append("static ANDROID_ATTRS: &[(u32, &str)] = &[")
    for rid, name in entries:
        out.append(f'    (0x{rid:08x}, "{name}"),')
    out.append("];")
    out.append("")

    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))
    print(f"wrote {len(entries)} entries to {dst} (from {src})")


if __name__ == "__main__":
    main()
