//! `ResTable_config`: the qualifiers of one resource value (`values-zh-rCN`,
//! `drawable-xxhdpi-v21`, ...), with AOSP's printing, matching and
//! "better match" rules.

use std::fmt;

pub const DENSITY_DEFAULT: u16 = 0;
pub const DENSITY_MEDIUM: u16 = 160;
pub const DENSITY_ANY: u16 = 0xfffe;
pub const DENSITY_NONE: u16 = 0xffff;

const MASK_SCREENSIZE: u8 = 0x0f;
const MASK_SCREENLONG: u8 = 0x30;
const MASK_LAYOUTDIR: u8 = 0xc0;
const MASK_SCREENROUND: u8 = 0x03;
const MASK_WIDE_COLOR_GAMUT: u8 = 0x03;
const MASK_HDR: u8 = 0x0c;
const MASK_UI_MODE_TYPE: u8 = 0x0f;
const MASK_UI_MODE_NIGHT: u8 = 0x30;
const MASK_KEYSHIDDEN: u8 = 0x03;
const MASK_NAVHIDDEN: u8 = 0x0c;
const MASK_GRAMMATICAL_GENDER: u8 = 0x03;
const KEYSHIDDEN_NO: u8 = 1;
const KEYSHIDDEN_SOFT: u8 = 3;

/// One `ResTable_config`. Fields missing from a short (older) on-disk
/// config read as zero, i.e. "any".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Config {
    pub mcc: u16,
    pub mnc: u16,
    pub language: [u8; 2],
    pub country: [u8; 2],
    pub orientation: u8,
    pub touchscreen: u8,
    pub density: u16,
    pub keyboard: u8,
    pub navigation: u8,
    pub input_flags: u8,
    pub grammatical_inflection: u8,
    pub screen_width: u16,
    pub screen_height: u16,
    pub sdk_version: u16,
    pub minor_version: u16,
    pub screen_layout: u8,
    pub ui_mode: u8,
    pub smallest_screen_width_dp: u16,
    pub screen_width_dp: u16,
    pub screen_height_dp: u16,
    pub locale_script: [u8; 4],
    pub locale_variant: [u8; 8],
    pub screen_layout2: u8,
    pub color_mode: u8,
    pub locale_script_was_computed: bool,
    pub locale_numbering_system: [u8; 8],
}

impl Config {
    /// Parse a config from `b`, which starts at the config's `size` field and
    /// is already limited to the bytes that belong to it.
    pub fn parse(b: &[u8]) -> Config {
        let u8_at = |o: usize| b.get(o).copied().unwrap_or(0);
        let u16_at = |o: usize| u16::from_le_bytes([u8_at(o), u8_at(o + 1)]);
        let arr = |o: usize, out: &mut [u8]| {
            for (i, x) in out.iter_mut().enumerate() {
                *x = u8_at(o + i);
            }
        };
        let mut c = Config {
            mcc: u16_at(4),
            mnc: u16_at(6),
            language: [u8_at(8), u8_at(9)],
            country: [u8_at(10), u8_at(11)],
            orientation: u8_at(12),
            touchscreen: u8_at(13),
            density: u16_at(14),
            keyboard: u8_at(16),
            navigation: u8_at(17),
            input_flags: u8_at(18),
            grammatical_inflection: u8_at(19),
            screen_width: u16_at(20),
            screen_height: u16_at(22),
            sdk_version: u16_at(24),
            minor_version: u16_at(26),
            screen_layout: u8_at(28),
            ui_mode: u8_at(29),
            smallest_screen_width_dp: u16_at(30),
            screen_width_dp: u16_at(32),
            screen_height_dp: u16_at(34),
            screen_layout2: u8_at(48),
            color_mode: u8_at(49),
            locale_script_was_computed: u8_at(52) != 0,
            ..Config::default()
        };
        arr(36, &mut c.locale_script);
        arr(40, &mut c.locale_variant);
        arr(53, &mut c.locale_numbering_system);
        c
    }

    /// The request [`crate::ResTable::resolve_default`] uses: no locale, the
    /// newest SDK, default density. Every unqualified (or `-vNN`) value
    /// matches it.
    pub fn any_device() -> Config {
        Config { sdk_version: u16::MAX, ..Config::default() }
    }

    pub fn is_default(&self) -> bool {
        *self == Config::default()
    }

    /// The language subtag (`en`, `fil`), unpacked.
    pub fn language(&self) -> String {
        unpack_language_or_region(self.language, b'a')
    }

    /// The region subtag (`US`, `419`), unpacked.
    pub fn region(&self) -> String {
        unpack_language_or_region(self.country, b'0')
    }

    /// `ResTable_config::match`: whether a value with this config may be
    /// used on a device described by `req`.
    pub fn matches(&self, req: &Config) -> bool {
        if self.mcc != 0 && self.mcc != req.mcc {
            return false;
        }
        if self.mnc != 0 && self.mnc != req.mnc {
            return false;
        }
        if self.language[0] != 0 {
            if self.language != req.language {
                return false;
            }
            if self.country[0] != 0 && self.country != req.country {
                return false;
            }
            if self.locale_script[0] != 0 && !self.locale_script_was_computed && self.locale_script != req.locale_script {
                return false;
            }
            if self.locale_variant[0] != 0 && self.locale_variant != req.locale_variant {
                return false;
            }
        }
        if self.grammatical_inflection != 0 && self.grammatical_inflection != req.grammatical_inflection {
            return false;
        }
        let both = |a: u8, b: u8| a != 0 && b != 0 && a != b;
        if both(self.screen_layout & MASK_LAYOUTDIR, req.screen_layout & MASK_LAYOUTDIR) {
            return false;
        }
        let size = self.screen_layout & MASK_SCREENSIZE;
        if size != 0 && size > req.screen_layout & MASK_SCREENSIZE {
            return false;
        }
        if both(self.screen_layout & MASK_SCREENLONG, req.screen_layout & MASK_SCREENLONG) {
            return false;
        }
        if both(self.screen_layout2 & MASK_SCREENROUND, req.screen_layout2 & MASK_SCREENROUND) {
            return false;
        }
        if both(self.color_mode & MASK_WIDE_COLOR_GAMUT, req.color_mode & MASK_WIDE_COLOR_GAMUT) {
            return false;
        }
        if both(self.color_mode & MASK_HDR, req.color_mode & MASK_HDR) {
            return false;
        }
        if both(self.ui_mode & MASK_UI_MODE_TYPE, req.ui_mode & MASK_UI_MODE_TYPE) {
            return false;
        }
        if both(self.ui_mode & MASK_UI_MODE_NIGHT, req.ui_mode & MASK_UI_MODE_NIGHT) {
            return false;
        }
        if self.smallest_screen_width_dp != 0 && self.smallest_screen_width_dp > req.smallest_screen_width_dp {
            return false;
        }
        if self.screen_width_dp != 0 && self.screen_width_dp > req.screen_width_dp {
            return false;
        }
        if self.screen_height_dp != 0 && self.screen_height_dp > req.screen_height_dp {
            return false;
        }
        if both(self.orientation, req.orientation) || both(self.touchscreen, req.touchscreen) {
            return false;
        }
        let keys = self.input_flags & MASK_KEYSHIDDEN;
        let req_keys = req.input_flags & MASK_KEYSHIDDEN;
        // A device with a soft keyboard also matches "keys exposed".
        if keys != 0 && req_keys != 0 && keys != req_keys && !(keys == KEYSHIDDEN_NO && req_keys == KEYSHIDDEN_SOFT) {
            return false;
        }
        if both(self.input_flags & MASK_NAVHIDDEN, req.input_flags & MASK_NAVHIDDEN) {
            return false;
        }
        if both(self.keyboard, req.keyboard) || both(self.navigation, req.navigation) {
            return false;
        }
        if self.screen_width != 0 && self.screen_width > req.screen_width {
            return false;
        }
        if self.screen_height != 0 && self.screen_height > req.screen_height {
            return false;
        }
        if self.sdk_version != 0 && self.sdk_version > req.sdk_version {
            return false;
        }
        if self.minor_version != 0 && self.minor_version != req.minor_version {
            return false;
        }
        true
    }

    /// `ResTable_config::isBetterThan(o, requested)`: among two configs that
    /// both match `req`, whether `self` is the more specific one. Qualifiers
    /// are compared in AOSP precedence order.
    pub fn is_better_than(&self, o: &Config, req: &Config) -> bool {
        // Present-vs-absent qualifier that the request also sets: present wins.
        macro_rules! prefer_set {
            ($a:expr, $b:expr, $r:expr) => {
                if ($a != 0) != ($b != 0) && $r != 0 {
                    return $a != 0;
                }
            };
        }
        // Both set and the request sets it: the larger (closer to the device) wins.
        macro_rules! prefer_larger {
            ($a:expr, $b:expr, $r:expr) => {
                if $a != $b && $r != 0 {
                    return $a > $b;
                }
            };
        }
        prefer_set!(self.mcc, o.mcc, req.mcc);
        prefer_set!(self.mnc, o.mnc, req.mnc);
        if req.language[0] != 0 {
            prefer_set!(self.language[0], o.language[0], 1);
            if self.language == o.language && req.country[0] != 0 {
                prefer_set!(self.country[0], o.country[0], 1);
            }
            if self.language == o.language && self.country == o.country && req.locale_variant[0] != 0 {
                prefer_set!(self.locale_variant[0], o.locale_variant[0], 1);
            }
        }
        prefer_set!(self.grammatical_inflection, o.grammatical_inflection, req.grammatical_inflection);
        prefer_set!(self.screen_layout & MASK_LAYOUTDIR, o.screen_layout & MASK_LAYOUTDIR, req.screen_layout & MASK_LAYOUTDIR);
        prefer_larger!(self.smallest_screen_width_dp, o.smallest_screen_width_dp, req.smallest_screen_width_dp);
        prefer_larger!(self.screen_width_dp, o.screen_width_dp, req.screen_width_dp);
        prefer_larger!(self.screen_height_dp, o.screen_height_dp, req.screen_height_dp);
        prefer_larger!(self.screen_layout & MASK_SCREENSIZE, o.screen_layout & MASK_SCREENSIZE, req.screen_layout & MASK_SCREENSIZE);
        prefer_set!(self.screen_layout & MASK_SCREENLONG, o.screen_layout & MASK_SCREENLONG, req.screen_layout & MASK_SCREENLONG);
        prefer_set!(self.screen_layout2 & MASK_SCREENROUND, o.screen_layout2 & MASK_SCREENROUND, req.screen_layout2 & MASK_SCREENROUND);
        prefer_set!(self.color_mode & MASK_HDR, o.color_mode & MASK_HDR, req.color_mode & MASK_HDR);
        prefer_set!(self.color_mode & MASK_WIDE_COLOR_GAMUT, o.color_mode & MASK_WIDE_COLOR_GAMUT, req.color_mode & MASK_WIDE_COLOR_GAMUT);
        prefer_set!(self.orientation, o.orientation, req.orientation);
        prefer_set!(self.ui_mode & MASK_UI_MODE_TYPE, o.ui_mode & MASK_UI_MODE_TYPE, req.ui_mode & MASK_UI_MODE_TYPE);
        prefer_set!(self.ui_mode & MASK_UI_MODE_NIGHT, o.ui_mode & MASK_UI_MODE_NIGHT, req.ui_mode & MASK_UI_MODE_NIGHT);
        if req.density != 0 && self.density != o.density {
            return density_better(self.density, o.density, req.density);
        }
        prefer_set!(self.touchscreen, o.touchscreen, req.touchscreen);
        prefer_set!(self.input_flags & MASK_KEYSHIDDEN, o.input_flags & MASK_KEYSHIDDEN, req.input_flags & MASK_KEYSHIDDEN);
        prefer_set!(self.keyboard, o.keyboard, req.keyboard);
        prefer_set!(self.input_flags & MASK_NAVHIDDEN, o.input_flags & MASK_NAVHIDDEN, req.input_flags & MASK_NAVHIDDEN);
        prefer_set!(self.navigation, o.navigation, req.navigation);
        prefer_larger!(self.screen_width, o.screen_width, req.screen_width);
        prefer_larger!(self.screen_height, o.screen_height, req.screen_height);
        prefer_larger!(self.sdk_version, o.sdk_version, req.sdk_version);
        prefer_set!(self.minor_version, o.minor_version, req.minor_version);
        false
    }
}

/// AOSP's density preference: `anydpi` beats everything, otherwise the
/// closest density, scaling down from a higher one being preferred.
fn density_better(this: u16, other: u16, requested: u16) -> bool {
    let norm = |d: u16| if d == DENSITY_DEFAULT { DENSITY_MEDIUM } else { d };
    let requested = if requested == DENSITY_ANY { DENSITY_MEDIUM as i64 } else { norm(requested) as i64 };
    let (this, other) = (norm(this), norm(other));
    if this == DENSITY_ANY {
        return true;
    }
    if other == DENSITY_ANY {
        return false;
    }
    let (mut h, mut l, mut i_am_bigger) = (this as i64, other as i64, true);
    if l > h {
        std::mem::swap(&mut h, &mut l);
        i_am_bigger = false;
    }
    if requested >= h {
        return i_am_bigger;
    }
    if l >= requested {
        return !i_am_bigger;
    }
    if (2 * l - requested) * h > requested * requested {
        !i_am_bigger
    } else {
        i_am_bigger
    }
}

/// Unpack a two-byte language/region field; three-letter codes are packed
/// into 15 bits with the high bit set.
fn unpack_language_or_region(b: [u8; 2], base: u8) -> String {
    if b[0] & 0x80 != 0 {
        let first = b[1] & 0x1f;
        let second = ((b[1] & 0xe0) >> 5) + ((b[0] & 0x03) << 3);
        let third = (b[0] & 0x7c) >> 2;
        return [first + base, second + base, third + base].iter().map(|&c| c as char).collect();
    }
    if b[0] == 0 {
        return String::new();
    }
    b.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect()
}

fn nul_str(b: &[u8]) -> String {
    b.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect()
}

impl fmt::Display for Config {
    /// Qualifier string exactly as `ResTable_config::toString` (and so
    /// `aapt2 dump resources`) prints it, e.g. `zh-rCN`, `night-v8`,
    /// `b+sr+Latn`, `sw600dp-land`; empty for the default config.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if self.mcc != 0 {
            parts.push(format!("mcc{}", self.mcc));
        }
        if self.mnc != 0 {
            // 0xffff stands for "mnc00"; AOSP (and aapt2) print it raw.
            parts.push(format!("mnc{}", self.mnc));
        }
        if self.language[0] != 0 {
            let script_provided = self.locale_script[0] != 0 && !self.locale_script_was_computed;
            if !script_provided && self.locale_variant[0] == 0 && self.locale_numbering_system[0] == 0 {
                let mut s = self.language();
                if self.country[0] != 0 {
                    s.push_str("-r");
                    s.push_str(&self.region());
                }
                parts.push(s);
            } else {
                let mut s = format!("b+{}", self.language());
                if script_provided {
                    s.push('+');
                    s.push_str(&nul_str(&self.locale_script));
                }
                if self.country[0] != 0 {
                    s.push('+');
                    s.push_str(&self.region());
                }
                if self.locale_variant[0] != 0 {
                    s.push('+');
                    s.push_str(&nul_str(&self.locale_variant));
                }
                if self.locale_numbering_system[0] != 0 {
                    s.push_str("+u+nu+");
                    s.push_str(&nul_str(&self.locale_numbering_system));
                }
                parts.push(s);
            }
        }
        match self.grammatical_inflection & MASK_GRAMMATICAL_GENDER {
            0 => {}
            1 => parts.push("neuter".into()),
            2 => parts.push("feminine".into()),
            _ => parts.push("masculine".into()),
        }
        match self.screen_layout & MASK_LAYOUTDIR {
            0 => {}
            0x40 => parts.push("ldltr".into()),
            0x80 => parts.push("ldrtl".into()),
            v => parts.push(format!("layoutDir={v}")),
        }
        if self.smallest_screen_width_dp != 0 {
            parts.push(format!("sw{}dp", self.smallest_screen_width_dp));
        }
        if self.screen_width_dp != 0 {
            parts.push(format!("w{}dp", self.screen_width_dp));
        }
        if self.screen_height_dp != 0 {
            parts.push(format!("h{}dp", self.screen_height_dp));
        }
        match self.screen_layout & MASK_SCREENSIZE {
            0 => {}
            1 => parts.push("small".into()),
            2 => parts.push("normal".into()),
            3 => parts.push("large".into()),
            4 => parts.push("xlarge".into()),
            v => parts.push(format!("screenLayoutSize={v}")),
        }
        match self.screen_layout & MASK_SCREENLONG {
            0 => {}
            0x10 => parts.push("notlong".into()),
            0x20 => parts.push("long".into()),
            v => parts.push(format!("screenLayoutLong={v}")),
        }
        match self.screen_layout2 & MASK_SCREENROUND {
            0 => {}
            1 => parts.push("notround".into()),
            2 => parts.push("round".into()),
            v => parts.push(format!("screenRound={v}")),
        }
        match self.color_mode & MASK_WIDE_COLOR_GAMUT {
            0 => {}
            1 => parts.push("nowidecg".into()),
            2 => parts.push("widecg".into()),
            v => parts.push(format!("wideColorGamut={v}")),
        }
        match self.color_mode & MASK_HDR {
            0 => {}
            4 => parts.push("lowdr".into()),
            8 => parts.push("highdr".into()),
            v => parts.push(format!("hdr={v}")),
        }
        match self.orientation {
            0 => {}
            1 => parts.push("port".into()),
            2 => parts.push("land".into()),
            3 => parts.push("square".into()),
            v => parts.push(format!("orientation={v}")),
        }
        match self.ui_mode & MASK_UI_MODE_TYPE {
            0 => {}
            2 => parts.push("desk".into()),
            3 => parts.push("car".into()),
            4 => parts.push("television".into()),
            5 => parts.push("appliance".into()),
            6 => parts.push("watch".into()),
            7 => parts.push("vrheadset".into()),
            v => parts.push(format!("uiModeType={v}")),
        }
        match self.ui_mode & MASK_UI_MODE_NIGHT {
            0 => {}
            0x10 => parts.push("notnight".into()),
            0x20 => parts.push("night".into()),
            v => parts.push(format!("uiModeNight={v}")),
        }
        match self.density {
            DENSITY_DEFAULT => {}
            120 => parts.push("ldpi".into()),
            160 => parts.push("mdpi".into()),
            213 => parts.push("tvdpi".into()),
            240 => parts.push("hdpi".into()),
            320 => parts.push("xhdpi".into()),
            480 => parts.push("xxhdpi".into()),
            640 => parts.push("xxxhdpi".into()),
            DENSITY_NONE => parts.push("nodpi".into()),
            DENSITY_ANY => parts.push("anydpi".into()),
            v => parts.push(format!("{v}dpi")),
        }
        match self.touchscreen {
            0 => {}
            1 => parts.push("notouch".into()),
            2 => parts.push("stylus".into()),
            3 => parts.push("finger".into()),
            v => parts.push(format!("touchscreen={v}")),
        }
        match self.input_flags & MASK_KEYSHIDDEN {
            0 => {}
            1 => parts.push("keysexposed".into()),
            2 => parts.push("keyshidden".into()),
            _ => parts.push("keyssoft".into()),
        }
        match self.keyboard {
            0 => {}
            1 => parts.push("nokeys".into()),
            2 => parts.push("qwerty".into()),
            3 => parts.push("12key".into()),
            v => parts.push(format!("keyboard={v}")),
        }
        match self.input_flags & MASK_NAVHIDDEN {
            0 => {}
            4 => parts.push("navexposed".into()),
            8 => parts.push("navhidden".into()),
            v => parts.push(format!("inputFlagsNavHidden={v}")),
        }
        match self.navigation {
            0 => {}
            1 => parts.push("nonav".into()),
            2 => parts.push("dpad".into()),
            3 => parts.push("trackball".into()),
            4 => parts.push("wheel".into()),
            v => parts.push(format!("navigation={v}")),
        }
        if self.screen_width != 0 || self.screen_height != 0 {
            parts.push(format!("{}x{}", self.screen_width, self.screen_height));
        }
        if self.sdk_version != 0 || self.minor_version != 0 {
            let mut s = format!("v{}", self.sdk_version);
            if self.minor_version != 0 {
                s.push_str(&format!(".{}", self.minor_version));
            }
            parts.push(s);
        }
        f.write_str(&parts.join("-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lang(l: &str, r: &str) -> Config {
        let mut c = Config::default();
        c.language.copy_from_slice(&l.as_bytes()[..2]);
        if !r.is_empty() {
            c.country.copy_from_slice(&r.as_bytes()[..2]);
        }
        c
    }

    #[test]
    fn prints_like_aapt() {
        assert_eq!(Config::default().to_string(), "");
        assert_eq!(lang("zh", "CN").to_string(), "zh-rCN");
        let c = Config { ui_mode: 0x20, sdk_version: 8, ..Config::default() };
        assert_eq!(c.to_string(), "night-v8");
        let c = Config { smallest_screen_width_dp: 600, orientation: 2, density: 480, sdk_version: 13, ..Config::default() };
        assert_eq!(c.to_string(), "sw600dp-land-xxhdpi-v13");
        let mut c = lang("sr", "");
        c.locale_script = *b"Latn";
        assert_eq!(c.to_string(), "b+sr+Latn");
        // Three-letter language packed into two bytes ("fil").
        let c = Config { language: [0xad, 0x05], ..Config::default() };
        assert_eq!(c.language(), "fil");
        // Region 419 is packed with base '0'.
        let c = Config { language: *b"es", country: [0xa4, 0x24], ..Config::default() };
        assert_eq!(c.to_string(), "es-r419");
    }

    #[test]
    fn matching_and_preference() {
        let req = Config { language: *b"zh", country: *b"CN", density: 480, sdk_version: 34, ..Config::default() };
        let def = Config::default();
        let zh = lang("zh", "");
        let zh_cn = lang("zh", "CN");
        let en = lang("en", "");
        assert!(def.matches(&req) && zh.matches(&req) && zh_cn.matches(&req));
        assert!(!en.matches(&req));
        assert!(zh.is_better_than(&def, &req));
        assert!(zh_cn.is_better_than(&zh, &req));
        let v21 = Config { sdk_version: 21, ..Config::default() };
        let v35 = Config { sdk_version: 35, ..Config::default() };
        assert!(v21.matches(&req) && !v35.matches(&req));
        assert!(v21.is_better_than(&def, &req));
        let x = Config { density: 320, ..Config::default() };
        let xxx = Config { density: 640, ..Config::default() };
        let any = Config { density: DENSITY_ANY, ..Config::default() };
        assert!(xxx.is_better_than(&x, &req), "scaling down from higher density is preferred");
        assert!(any.is_better_than(&xxx, &req));
    }
}
