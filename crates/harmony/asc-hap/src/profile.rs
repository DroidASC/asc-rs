//! The profiles `module.json` names for pages: the page list
//! (`"pages": "$profile:main_pages"`) and the navigation route table
//! (`"routerMap": "$profile:router_map"`), both JSON files under
//! `resources/base/profile/`.

use crate::HapError;
use crate::record;
use crate::value::{self, Findings, Line, Note, Obj};

/// A parsed page list: `{"src": ["pages/Index", …]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageList {
    /// Page paths relative to the module's `ets/` directory, without
    /// extension, in file order.
    pub pages: Vec<String>,
    /// Fields that were present but wrongly typed, and so skipped.
    pub notes: Vec<Note>,
}

impl PageList {
    /// Read a page list.
    ///
    /// # Errors
    ///
    /// Only when `bytes` is not JSON or its root is not an object.
    pub fn parse(bytes: &[u8]) -> Result<Self, HapError> {
        let map = value::parse_object(bytes)?;
        let mut findings = Findings::default();
        let mut root = Obj::root(&map, &mut findings);
        let pages = root.strings("src");
        // What else the file holds (`window`, …) says nothing about code.
        Ok(PageList { pages, notes: findings.notes })
    }

    /// The `srcEntry` spelling of `page`, which
    /// [`ModuleJson::record_names`](crate::ModuleJson::record_names) takes:
    /// `./ets/pages/Index` for `pages/Index`.
    pub fn src_entry(page: &str) -> String {
        format!("./ets/{}", page.trim_start_matches("./").trim_start_matches('/'))
    }

    /// The summary line of `page`: `page pages/Index`.
    pub fn line(page: &str) -> String {
        Line::new("page").word(page).end()
    }
}

/// A parsed route table: `{"routerMap": [{…}, …]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouterMap {
    /// In file order.
    pub routes: Vec<Route>,
    /// Fields that were present but wrongly typed, and so skipped.
    pub notes: Vec<Note>,
}

/// One route: a name the navigation stack is pushed with, and the builder
/// function that makes its page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    pub name: Option<String>,
    /// The source file of the page, relative to the root of the package
    /// that has it: `src/main/ets/pages/Detail.ets`.
    pub page_source_file: Option<String>,
    /// The `@Builder` function of that file the system calls.
    pub build_function: Option<String>,
    /// The module request of the page's record, as the build wrote it:
    /// `@normalized:N&<module>&<bundle>&<package>/<path>&<version>`.
    pub ohmurl: Option<String>,
    /// The package that has the page, when it is not the module itself.
    pub package_name: Option<String>,
    pub module_name: Option<String>,
    pub bundle_name: Option<String>,
}

impl Route {
    /// The record [`Route::ohmurl`] names: `<bundle>&<package>/<path>&<version>`
    /// of a `@normalized:N&<module>&<bundle>&<package>/<path>&<version>`
    /// request. `None` for any other form (a native library, a system module).
    pub fn ohmurl_record(&self) -> Option<&str> {
        let rest = self.ohmurl.as_deref()?.strip_prefix("@normalized:N&")?;
        let (_module, record) = rest.split_once('&')?;
        // `<bundle>&<path>&<version>`: two more `&`, and a path between them.
        let (_bundle, tail) = record.split_once('&')?;
        let (path, _version) = tail.rsplit_once('&')?;
        (!path.is_empty()).then_some(record)
    }

    /// The summary line of the route:
    /// `route NAME buildFunction=F source=FILE`, with `package=NAME` when
    /// the page is in another package than the module.
    pub fn line(&self) -> String {
        Line::new("route")
            .word(self.name.as_deref().unwrap_or("-"))
            .opt("buildFunction", self.build_function.as_deref())
            .opt("source", self.page_source_file.as_deref())
            .opt_present("package", self.package_name.as_deref())
            .end()
    }

    /// The module [`Route::ohmurl`] says the record is in; empty for the
    /// module that has the route table.
    pub fn ohmurl_module(&self) -> Option<&str> {
        let rest = self.ohmurl.as_deref()?.strip_prefix("@normalized:N&")?;
        rest.split_once('&').map(|(module, _)| module)
    }

    /// [`Route::page_source_file`] without its extension, behind the package
    /// that has it (`default_package` when the route names none):
    /// `<package>/src/main/ets/pages/Detail`, the part of a normalized
    /// record name between its `&`.
    pub fn record_path(&self, default_package: Option<&str>) -> Option<String> {
        let source = self.page_source_file.as_deref()?.trim_start_matches("./").trim_start_matches('/');
        let package = self.package_name.as_deref().or(default_package)?;
        Some(format!("{package}/{}", record::strip_source_extension(source)))
    }
}

impl RouterMap {
    /// Read a route table.
    ///
    /// # Errors
    ///
    /// Only when `bytes` is not JSON or its root is not an object.
    pub fn parse(bytes: &[u8]) -> Result<Self, HapError> {
        let map = value::parse_object(bytes)?;
        let mut findings = Findings::default();
        let mut root = Obj::root(&map, &mut findings);
        let routes = root.objects("routerMap", |route| Route {
            name: route.str("name"),
            page_source_file: route.str("pageSourceFile"),
            build_function: route.str("buildFunction"),
            ohmurl: route.str("ohmurl"),
            package_name: route.str("packageName"),
            module_name: route.str("moduleName"),
            bundle_name: route.str("bundleName"),
        });
        // `data` / `customData` of a route are the application's own.
        Ok(RouterMap { routes, notes: findings.notes })
    }
}
