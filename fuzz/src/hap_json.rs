//! `asc-hap`: the JSON documents of a package (`module.json`, `pack.info`,
//! `pkgContextInfo.json`, the page list, the route table and the source
//! maps), read and summarised.

use asc_hap::{ModuleJson, PackInfo, PageList, PkgContextInfo, RouterMap, SourceMaps};

pub fn run(data: &[u8]) {
    let packages = PkgContextInfo::parse(data).ok();
    if let Some(packages) = &packages {
        let _ = (packages.summary(), packages.pretty(), packages.locate("&entry/src/main/ets/pages/Index&").is_some());
        for package in packages.packages() {
            let _ = package.entry_record_name();
        }
    }
    if let Ok(module) = ModuleJson::parse(data) {
        let _ = (module.summary(), module.pretty());
        for ability in module.components() {
            let _ = (ability.is_exported(), ability.deep_links());
            if let Some(src) = &ability.src_entry {
                let _ = module.record_names(src, packages.as_ref()).candidates().len();
            }
        }
    }
    if let Ok(pack) = PackInfo::parse(data) {
        let _ = (pack.summary(), pack.pretty());
    }
    if let Ok(pages) = PageList::parse(data) {
        for page in &pages.pages {
            let _ = (PageList::src_entry(page), PageList::line(page));
        }
    }
    if let Ok(routes) = RouterMap::parse(data) {
        for route in &routes.routes {
            let _ = (route.line(), route.ohmurl_record(), route.ohmurl_module(), route.record_path(Some("com.x.y")));
        }
    }
    if let Ok(maps) = SourceMaps::index(data) {
        let keys: Vec<String> = maps.keys().take(16).map(str::to_owned).collect();
        for key in keys {
            if let Some(Ok(module)) = maps.module(data, &key) {
                let _ = (module.mapped_sources(), module.source_line(12), module.source_lines().len());
            }
        }
    }
}
