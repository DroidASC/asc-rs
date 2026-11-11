//! Call sites and method handles of a real d8 output (`tests/d8/CallSites.java`).

use asc_dex::encoded::EncodedValue;
use asc_dex::{CallSite, Dex, MethodHandleKind, map_type};

const CALL_SITES_DEX: &[u8] = include_bytes!("d8/callsites.dex");

fn proto(dex: &Dex<'_>, idx: u32) -> String {
    let p = dex.proto_id(idx).unwrap();
    let params: String = dex.proto_params(idx).unwrap().into_iter().map(|t| dex.type_descriptor(t.into()).unwrap()).collect();
    format!("({params}){}", dex.type_descriptor(p.return_type_idx).unwrap())
}

fn handle(dex: &Dex<'_>, idx: u32) -> (MethodHandleKind, String) {
    let h = dex.method_handle(idx).unwrap();
    assert!(!h.kind.is_field_accessor());
    (h.kind, dex.method_display(h.field_or_method_idx.into()).unwrap())
}

#[test]
fn lambda_call_sites_bootstrap_through_lambda_metafactory() {
    let dex = Dex::parse(CALL_SITES_DEX).unwrap();
    let map = dex.map().unwrap();
    assert_eq!(map.find(map_type::METHOD_HANDLE).map(|m| m.size), Some(3));
    assert_eq!(map.find(map_type::STRING_ID).map(|m| m.size), Some(dex.string_count()));
    assert_eq!(map.iter().collect::<Vec<_>>(), dex.map_list());

    assert_eq!(dex.method_handle_count().unwrap(), 3);
    assert_eq!(dex.call_site_count().unwrap(), 2);
    let metafactory = (MethodHandleKind::InvokeStatic, "Ljava/lang/invoke/LambdaMetafactory;->metafactory".to_string());

    // `(a, b) -> a * b + x` captured as an IntBinaryOperator.
    let CallSite { bootstrap, method_name, method_type, extra_args, .. } = dex.call_site(0).unwrap();
    assert_eq!(handle(&dex, bootstrap), metafactory);
    assert_eq!(dex.string(method_name).unwrap(), "applyAsInt");
    assert_eq!(proto(&dex, method_type), "(I)Ljava/util/function/IntBinaryOperator;");
    let [EncodedValue::MethodType(erased), EncodedValue::MethodHandle(implementation), EncodedValue::MethodType(instantiated)] =
        extra_args[..]
    else {
        panic!("{extra_args:?}");
    };
    assert_eq!(proto(&dex, erased), "(II)I");
    assert_eq!(handle(&dex, implementation), (MethodHandleKind::InvokeStatic, "LCallSites;->lambda$lambdas$0".to_string()));
    assert_eq!(proto(&dex, instantiated), "(II)I");

    // `String::new` as a Supplier<String>.
    let site = dex.call_site(1).unwrap();
    assert_eq!(handle(&dex, site.bootstrap), metafactory);
    assert_eq!(dex.string(site.method_name).unwrap(), "get");
    assert_eq!(proto(&dex, site.method_type), "()Ljava/util/function/Supplier;");
    let EncodedValue::MethodHandle(constructor) = site.extra_args[1] else { panic!("{:?}", site.extra_args) };
    assert_eq!(handle(&dex, constructor), (MethodHandleKind::InvokeConstructor, "Ljava/lang/String;-><init>".to_string()));
}

/// Every truncation and every single-byte corruption of the file is an
/// error or a value, never a panic.
#[test]
fn damaged_files_never_panic() {
    let probe = |data: &[u8]| {
        let Ok(dex) = Dex::parse(data) else { return };
        let _ = dex.map();
        for idx in [0, 1, 2, 3, u32::MAX] {
            let _ = dex.method_handle(idx);
            let _ = dex.call_site(idx);
        }
    };
    for len in 0..CALL_SITES_DEX.len() {
        probe(&CALL_SITES_DEX[..len]);
    }
    let mut data = CALL_SITES_DEX.to_vec();
    for i in 0..data.len() {
        for byte in [0xff, 0x80, 0x00] {
            let saved = std::mem::replace(&mut data[i], byte);
            probe(&data);
            data[i] = saved;
        }
    }
}
