//! Element-tree view of a binary XML document, for code that needs to read
//! attributes (manifest summary, network security config, ...) rather than
//! print the document.

use super::*;

/// One element of a parsed binary XML document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Element {
    /// Namespace URI (empty for none).
    pub ns: String,
    pub name: String,
    pub attrs: Vec<Attribute>,
    pub children: Vec<Element>,
    /// Character data directly inside the element, trimmed and joined.
    pub text: String,
}

/// One attribute: its typed value plus the text [`decode`] would print.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Namespace URI (empty for none). Framework attributes identified by
    /// resource id get [`ANDROID_NS`] even when the namespace was stripped.
    pub ns: String,
    pub name: String,
    /// Resource id from the resource map, if any.
    pub res_id: Option<u32>,
    pub kind: u8,
    pub data: u32,
    /// Rendered value: the raw string, or the formatted typed value.
    pub value: String,
}

/// The `android:` namespace URI.
pub const ANDROID_NS: &str = ANDROID_NS_URI;

impl Attribute {
    pub fn is_android(&self) -> bool {
        self.ns == ANDROID_NS_URI
    }

    /// The value as a boolean when it is a literal boolean (or a
    /// `"true"`/`"false"` string).
    pub fn as_bool(&self) -> Option<bool> {
        match self.kind {
            TYPE_INT_BOOLEAN => Some(self.data != 0),
            TYPE_STRING => self.value.trim().parse().ok(),
            _ => None,
        }
    }

    /// The value as an integer when it is a literal integer (or a numeric string).
    pub fn as_int(&self) -> Option<i64> {
        match self.kind {
            TYPE_INT_DEC | TYPE_INT_HEX => Some(self.data as i32 as i64),
            TYPE_STRING => self.value.trim().parse().ok(),
            _ => None,
        }
    }

    /// The referenced resource id when the value is a reference.
    pub fn reference(&self) -> Option<u32> {
        matches!(self.kind, TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE).then_some(self.data).filter(|&d| d != 0)
    }
}

impl Element {
    /// Attribute `name` in the `android:` namespace.
    pub fn android(&self, name: &str) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.is_android() && a.name == name)
    }

    /// Attribute `name` without a namespace (e.g. `package` on `<manifest>`).
    pub fn plain(&self, name: &str) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.ns.is_empty() && a.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
}

/// Parse a binary XML document and return its root element. `resolver`
/// names app attributes and references as in [`decode_with`].
pub fn parse_tree(data: &[u8], resolver: Option<&dyn Resolver>) -> Result<Element> {
    if data.len() < 8 || u16_at(data, 0)? != RES_XML_TYPE {
        return Err(AxmlError::NotAxml);
    }
    let file_size = (u32_at(data, 4)? as usize).min(data.len());
    let mut pool: Option<StringPool> = None;
    let mut resource_ids: Vec<u32> = Vec::new();
    // Open elements; index 0 is a synthetic document node.
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut p = 8usize;
    while p + 8 <= file_size {
        let kind = u16_at(data, p)?;
        let header_size = u16_at(data, p + 2)? as usize;
        let size = u32_at(data, p + 4)? as usize;
        if size < 8 {
            break;
        }
        if header_size > size {
            return Err(AxmlError::Malformed("chunk header larger than chunk"));
        }
        let chunk_end = p.checked_add(size).map_or(file_size, |e| e.min(file_size));
        let ext = p + header_size;
        match kind {
            RES_STRING_POOL_TYPE => pool = Some(StringPool::parse(data, p, chunk_end)?),
            RES_XML_RESOURCE_MAP_TYPE => {
                let count = chunk_end.saturating_sub(ext) / 4;
                resource_ids = (0..count).map(|i| u32_at(data, ext + i * 4)).collect::<Result<_>>()?;
            }
            RES_XML_START_ELEMENT_TYPE => {
                let sp = pool.as_ref().ok_or(AxmlError::NoStringPool)?;
                let ns = sp.get(u32_at(data, ext)?).unwrap_or("").to_string();
                let name = sp.get(u32_at(data, ext + 4)?).unwrap_or("").to_string();
                let attr_start = u16_at(data, ext + 8)? as usize;
                let attr_size = (u16_at(data, ext + 10)? as usize).max(ATTRIBUTE_SIZE);
                let attr_count = u16_at(data, ext + 12)? as usize;
                let base = ext + attr_start;
                let mut attrs = Vec::with_capacity(attr_count);
                for i in 0..attr_count {
                    let a = i.checked_mul(attr_size).and_then(|o| base.checked_add(o)).ok_or(AxmlError::Truncated(base))?;
                    if a + ATTRIBUTE_SIZE > chunk_end {
                        return Err(AxmlError::Truncated(a));
                    }
                    let mut ans = sp.get(u32_at(data, a)?).unwrap_or("").to_string();
                    let aname_idx = u32_at(data, a + 4)?;
                    let raw = u32_at(data, a + 8)?;
                    let dtype = u8_at(data, a + 15)?;
                    let dval = u32_at(data, a + 16)?;
                    let (aname, from_framework) = resolve_attr_name(sp.get(aname_idx).unwrap_or(""), aname_idx, &resource_ids, resolver);
                    if from_framework {
                        ans = ANDROID_NS_URI.to_string();
                    }
                    // A raw string wins over the typed value, as in `decode`.
                    let (kind, data_value, value) = if raw != 0xFFFF_FFFF && matches!(dtype, TYPE_STRING | TYPE_NULL) {
                        (TYPE_STRING, raw, sp.get(raw).unwrap_or("").to_string())
                    } else {
                        (dtype, dval, format_value_with(dtype, dval, sp, resolver))
                    };
                    let res_id = resource_ids.get(aname_idx as usize).copied();
                    attrs.push(Attribute { ns: ans, name: aname, res_id, kind, data: data_value, value });
                }
                stack.push(Element { ns, name, attrs, children: Vec::new(), text: String::new() });
            }
            RES_XML_END_ELEMENT_TYPE => {
                if stack.len() > 1 {
                    let el = stack.pop().expect("len > 1");
                    stack.last_mut().expect("document node").children.push(el);
                }
            }
            RES_XML_CDATA_TYPE => {
                let sp = pool.as_ref().ok_or(AxmlError::NoStringPool)?;
                let text = sp.get(u32_at(data, ext)?).unwrap_or("").trim();
                let cur = stack.last_mut().expect("document node");
                if !text.is_empty() {
                    if !cur.text.is_empty() {
                        cur.text.push(' ');
                    }
                    cur.text.push_str(text);
                }
            }
            _ => {}
        }
        p = chunk_end;
    }
    while stack.len() > 1 {
        let el = stack.pop().expect("len > 1");
        stack.last_mut().expect("document node").children.push(el);
    }
    stack.pop().and_then(|doc| doc.children.into_iter().next()).ok_or(AxmlError::Malformed("no root element"))
}
