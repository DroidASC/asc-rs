//! Qualifiers: what a resource directory name (`base`, `zh_CN`,
//! `en_US-vertical-phone-dark`) compiles to.

use std::fmt;

/// What a qualifier restricts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QualifierKey {
    Language,
    Region,
    /// Screen density (`sdpi` .. `xxxldpi`), stored as dots per inch.
    Density,
    Orientation,
    Device,
    Script,
    /// `dark` / `light`.
    ColorMode,
    Mcc,
    Mnc,
    InputDevice,
    /// A key this crate has no name for.
    Other(u32),
}

impl QualifierKey {
    fn from_code(code: u32) -> QualifierKey {
        match code {
            0 => QualifierKey::Language,
            1 => QualifierKey::Region,
            2 => QualifierKey::Density,
            3 => QualifierKey::Orientation,
            4 => QualifierKey::Device,
            5 => QualifierKey::Script,
            6 => QualifierKey::ColorMode,
            7 => QualifierKey::Mcc,
            8 => QualifierKey::Mnc,
            10 => QualifierKey::InputDevice,
            other => QualifierKey::Other(other),
        }
    }
}

/// The key's name: `language`, `colorMode`, `key9` for an unnamed one.
impl fmt::Display for QualifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            QualifierKey::Language => "language",
            QualifierKey::Region => "region",
            QualifierKey::Density => "density",
            QualifierKey::Orientation => "orientation",
            QualifierKey::Device => "device",
            QualifierKey::Script => "script",
            QualifierKey::ColorMode => "colorMode",
            QualifierKey::Mcc => "mcc",
            QualifierKey::Mnc => "mnc",
            QualifierKey::InputDevice => "inputDevice",
            QualifierKey::Other(code) => return write!(f, "key{code}"),
        })
    }
}

/// One key of a qualifier set with its stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Qualifier {
    pub key: QualifierKey,
    /// The stored number: packed letters for language, script and region,
    /// dots per inch for density, an enumerator for the rest.
    pub value: u32,
}

impl Qualifier {
    pub(super) fn from_raw(key: u32, value: u32) -> Qualifier {
        Qualifier { key: QualifierKey::from_code(key), value }
    }

    /// Language, script and region pack their letters into the number,
    /// first letter in the highest used byte: `zh` is `0x7a68`.
    fn letters(self) -> String {
        self.value.to_be_bytes().into_iter().filter(|&b| b != 0).map(|b| if b.is_ascii_graphic() { char::from(b) } else { '?' }).collect()
    }

    fn enumerator(self, names: &[(u32, &'static str)]) -> Option<&'static str> {
        names.iter().find(|(value, _)| *value == self.value).map(|(_, name)| *name)
    }
}

const DENSITIES: &[(u32, &str)] = &[(120, "sdpi"), (160, "mdpi"), (240, "ldpi"), (320, "xldpi"), (480, "xxldpi"), (640, "xxxldpi")];
const ORIENTATIONS: &[(u32, &str)] = &[(0, "vertical"), (1, "horizontal")];
const DEVICES: &[(u32, &str)] = &[(0, "phone"), (1, "tablet"), (2, "car"), (3, "pad"), (4, "tv"), (6, "wearable"), (7, "2in1")];
const COLOR_MODES: &[(u32, &str)] = &[(0, "dark"), (1, "light")];
const INPUT_DEVICES: &[(u32, &str)] = &[(0, "pointingdevice")];

/// The value as it is spelled in a resource directory name: `zh`, `CN`,
/// `dark`, `xldpi`, `mcc460`. A value without a spelling is
/// `<key>=<number>`.
impl fmt::Display for Qualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let named = match self.key {
            QualifierKey::Language | QualifierKey::Script | QualifierKey::Region => return f.write_str(&self.letters()),
            QualifierKey::Mcc => return write!(f, "mcc{}", self.value),
            QualifierKey::Mnc => return write!(f, "mnc{}", self.value),
            QualifierKey::Density => self.enumerator(DENSITIES),
            QualifierKey::Orientation => self.enumerator(ORIENTATIONS),
            QualifierKey::Device => self.enumerator(DEVICES),
            QualifierKey::ColorMode => self.enumerator(COLOR_MODES),
            QualifierKey::InputDevice => self.enumerator(INPUT_DEVICES),
            QualifierKey::Other(_) => None,
        };
        match named {
            Some(name) => f.write_str(name),
            None => write!(f, "{}={}", self.key, self.value),
        }
    }
}

/// The qualifiers one value of a resource was defined under. Empty is the
/// `base` directory, the value used when nothing more specific matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Qualifiers {
    params: Vec<Qualifier>,
}

impl Qualifiers {
    pub(super) fn new(params: Vec<Qualifier>) -> Qualifiers {
        Qualifiers { params }
    }

    /// The keys in stored order.
    pub fn params(&self) -> &[Qualifier] {
        &self.params
    }

    /// Whether this is the unqualified `base` set.
    pub fn is_base(&self) -> bool {
        self.params.is_empty()
    }

    /// The stored value of `key`, when the set restricts it.
    pub fn get(&self, key: QualifierKey) -> Option<u32> {
        self.params.iter().find(|p| p.key == key).map(|p| p.value)
    }
}

/// The directory name: `base`, `zh_CN`, `en_US-vertical-phone-dark`.
/// Script, region and mnc attach to what precedes them with `_`, every
/// other key with `-`.
impl fmt::Display for Qualifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.params.is_empty() {
            return f.write_str("base");
        }
        for (i, param) in self.params.iter().enumerate() {
            let attaches = matches!(param.key, QualifierKey::Script | QualifierKey::Region | QualifierKey::Mnc);
            if i > 0 {
                f.write_str(if attaches { "_" } else { "-" })?;
            }
            write!(f, "{param}")?;
        }
        Ok(())
    }
}
