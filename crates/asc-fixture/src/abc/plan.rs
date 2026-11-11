//! What does not depend on offsets: which region every class and method
//! belongs to, the content of each region's tables, and the order literal
//! arrays and annotations are written in.

use std::collections::{BTreeSet, HashMap, HashSet};

use asc_abc::Version;

use super::{AbcAnnotation, AbcBuilder, AbcFieldValue, AbcLiteral, AbcModule, AbcRecord, AbcType, AnnotationKind, Op};

/// An item other items refer to by file offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum Sym {
    Str(String),
    /// A record or foreign class, by name.
    Class(String),
    /// A function, by record and raw name.
    Method(String, String),
    /// Position in [`Plan::literals`].
    Literal(usize),
    /// The 8-byte value of field `.1` of record `.0`.
    WideValue(usize, usize),
    /// The prototype of functions with this many arguments.
    Proto(u32),
    /// Position in [`Plan::annotations`].
    Annotation(usize),
    /// Code of function `.1` of record `.0`.
    Code(usize, usize),
    DebugInfo(usize, usize),
}

/// What sits in the literal array area, in file order.
#[derive(Debug, Clone, Copy)]
pub(super) enum LiteralItem<'a> {
    Array(&'a [AbcLiteral]),
    ScopeNames(&'a [String]),
    /// A module request phase table: listed with the literal arrays, but
    /// a plain counted byte string.
    Phases(&'a [u8]),
    Module(&'a AbcModule),
}

/// The first item of a region.
#[derive(Debug, Clone, Copy)]
pub(super) enum RegionStart {
    Class(usize),
    Method(usize, usize),
}

#[derive(Debug)]
pub(super) struct Region {
    pub(super) start: RegionStart,
    /// The entity table: strings, methods and literal arrays in the order
    /// the region's code first mentions them.
    pub(super) entities: Vec<Sym>,
    pub(super) ids: HashMap<Sym, u16>,
    /// Class table, first part: primitive type codes in ascending order.
    pub(super) primitives: BTreeSet<u8>,
    /// Class table, second part: classes by [`Plan::class_order`], which is
    /// their order in the file.
    pub(super) classes: BTreeSet<usize>,
    /// Proto table (versions before 12): argument counts.
    pub(super) protos: Vec<u32>,
    methods: usize,
}

impl Region {
    fn new(start: RegionStart) -> Region {
        Region {
            start,
            entities: Vec::new(),
            ids: HashMap::new(),
            primitives: BTreeSet::new(),
            classes: BTreeSet::new(),
            protos: Vec::new(),
            methods: 0,
        }
    }

    fn add_entity(&mut self, sym: &Sym) {
        if !self.ids.contains_key(sym) {
            let id = u16::try_from(self.entities.len()).expect("the planner keeps regions within 65536 entities");
            self.ids.insert(sym.clone(), id);
            self.entities.push(sym.clone());
        }
    }

    pub(super) fn primitive_idx(&self, code: u8) -> u16 {
        let rank = self.primitives.iter().position(|&known| known == code).expect("field types are collected by the planner");
        u16::try_from(rank).expect("at most 13 primitive types")
    }

    pub(super) fn class_idx(&self, order: usize) -> u16 {
        let rank = self.classes.iter().position(|&known| known == order).expect("classes a region refers to are collected by the planner");
        u16::try_from(self.primitives.len() + rank).expect("class table index fits in 16 bits")
    }

    pub(super) fn class_table_len(&self) -> usize {
        self.primitives.len() + self.classes.len()
    }
}

pub(super) struct Plan<'a> {
    pub(super) builder: &'a AbcBuilder,
    /// Whether regions have field / proto tables and methods a prototype.
    pub(super) has_protos: bool,
    pub(super) has_literal_index: bool,
    /// Foreign classes, then records: the order classes are written in.
    pub(super) class_names: Vec<&'a str>,
    class_order: HashMap<&'a str, usize>,
    pub(super) literals: Vec<LiteralItem<'a>>,
    /// Position in `literals` of the array or module record behind a field.
    pub(super) field_literals: HashMap<(usize, usize), usize>,
    /// Position in `literals` of `LiteralArrayId(0)`.
    pub(super) declared_literals_base: usize,
    pub(super) regions: Vec<Region>,
    pub(super) class_region: Vec<usize>,
    pub(super) method_region: Vec<Vec<usize>>,
    /// Every annotation, in the order its holder is written.
    pub(super) annotations: Vec<&'a AbcAnnotation>,
}

impl<'a> Plan<'a> {
    pub(super) fn new(builder: &'a AbcBuilder) -> Plan<'a> {
        let records = &builder.records;
        let class_names: Vec<&str> =
            builder.foreign_classes.iter().chain(records.iter().map(|record| &record.name)).map(String::as_str).collect();
        let mut class_order = HashMap::new();
        for (order, &name) in class_names.iter().enumerate() {
            assert!(class_order.insert(name, order).is_none(), "class `{name}` declared twice");
        }

        let mut literals = Vec::new();
        let mut field_literals = HashMap::new();
        for (r, record) in records.iter().enumerate() {
            for (f, field) in record.fields.iter().enumerate() {
                let item = match &field.value {
                    AbcFieldValue::ScopeNames(names) => LiteralItem::ScopeNames(names),
                    AbcFieldValue::Module(module) => LiteralItem::Module(module),
                    AbcFieldValue::ModuleRequestPhases(phases) => LiteralItem::Phases(phases),
                    AbcFieldValue::None
                    | AbcFieldValue::Int(_)
                    | AbcFieldValue::Raw(_)
                    | AbcFieldValue::Wide(_)
                    | AbcFieldValue::String(_)
                    | AbcFieldValue::Array(_) => continue,
                };
                field_literals.insert((r, f), literals.len());
                literals.push(item);
            }
        }
        let declared_literals_base = literals.len();
        literals.extend(builder.literal_arrays.iter().map(|items| LiteralItem::Array(items)));

        let version = Version(builder.version);
        let mut plan = Plan {
            builder,
            has_protos: builder.version[0] < 12,
            has_literal_index: version <= Version::LAST_WITH_LITERAL_INDEX,
            class_names,
            class_order,
            literals,
            field_literals,
            declared_literals_base,
            regions: Vec::new(),
            class_region: Vec::new(),
            method_region: Vec::new(),
            annotations: Vec::new(),
        };
        plan.assign_regions();
        plan.collect_annotations();
        plan
    }

    pub(super) fn order_of(&self, class: &str) -> usize {
        *self.class_order.get(class).unwrap_or_else(|| panic!("class `{class}` is neither a record nor a foreign class of the file"))
    }

    /// The entity an instruction operand of `record`'s code names.
    pub(super) fn entity_sym(&self, record: &AbcRecord, operand: &Op) -> Sym {
        match operand {
            Op::Str(text) => Sym::Str(text.clone()),
            Op::Method(name) => Sym::Method(record.name.clone(), name.clone()),
            Op::MethodIn { record, name } => Sym::Method(record.clone(), name.clone()),
            Op::Literal(id) => Sym::Literal(self.declared_literals_base + id.0),
            Op::Num(_) | Op::Float(_) | Op::Label(_) | Op::Id(_) => unreachable!("not a symbolic id: {operand:?}"),
        }
    }

    /// Walk classes and methods in file order like
    /// `ItemContainer::AddIndexDependecies` does, opening a new region where
    /// the builder asks for one or the entity table would overflow.
    fn assign_regions(&mut self) {
        let builder = self.builder;
        for (r, record) in builder.records.iter().enumerate() {
            if self.regions.is_empty() || builder.region_starts.contains(&record.name) {
                self.regions.push(Region::new(RegionStart::Class(r)));
            }
            let own_order = self.order_of(&record.name);
            let field_types: Vec<_> = record.fields.iter().map(|field| field.ty.primitive_code().ok_or(&field.ty)).collect();
            let referenced: Vec<usize> = field_types
                .iter()
                .filter_map(|ty| if let Err(AbcType::Record(name)) = ty { Some(name) } else { None })
                .chain(&record.interfaces)
                .map(|name| self.order_of(name))
                .collect();
            let region = self.regions.last_mut().expect("a region was opened above");
            region.classes.insert(own_order);
            region.classes.extend(referenced);
            region.primitives.extend(field_types.iter().filter_map(|ty| ty.ok()));
            self.class_region.push(self.regions.len() - 1);

            let mut method_regions = Vec::with_capacity(record.functions.len());
            for (f, function) in record.functions.iter().enumerate() {
                let entities: Vec<Sym> =
                    function.code.iter().flat_map(|code| code.asm.symbolic_ids()).map(|operand| self.entity_sym(record, operand)).collect();
                let distinct: HashSet<&Sym> = entities.iter().collect();
                let region = self.regions.last().expect("a region was opened above");
                let added = distinct.iter().filter(|sym| !region.ids.contains_key(**sym)).count();
                let full = builder.methods_per_region.is_some_and(|limit| region.methods >= limit);
                if full || region.entities.len() + added > builder.max_region_entities {
                    assert!(
                        distinct.len() <= builder.max_region_entities,
                        "function `{}` refers to {} entities, a region holds {}",
                        function.name,
                        distinct.len(),
                        builder.max_region_entities
                    );
                    self.regions.push(Region::new(RegionStart::Method(r, f)));
                }
                let has_protos = self.has_protos;
                let region = self.regions.last_mut().expect("a region was opened above");
                region.methods += 1;
                region.classes.insert(own_order);
                entities.iter().for_each(|sym| region.add_entity(sym));
                let num_args = function.code.as_ref().map_or(0, |code| code.num_args);
                if has_protos && !region.protos.contains(&num_args) {
                    region.protos.push(num_args);
                }
                method_regions.push(self.regions.len() - 1);
            }
            self.method_region.push(method_regions);
        }
    }

    /// Annotation items follow all classes, so they sit in the last region
    /// and name their class through its class table.
    fn collect_annotations(&mut self) {
        let records = &self.builder.records;
        self.annotations = records
            .iter()
            .flat_map(|record| {
                let fields = record.fields.iter().flat_map(|field| Holder::Field.ordered(&field.annotations));
                let functions = record.functions.iter().flat_map(|function| Holder::Method.ordered(&function.annotations));
                Holder::Class.ordered(&record.annotations).into_iter().chain(fields).chain(functions)
            })
            .collect();
        let orders: Vec<usize> = self.annotations.iter().map(|annotation| self.order_of(&annotation.class)).collect();
        if let Some(last) = self.regions.last_mut() {
            last.classes.extend(orders);
        }
    }
}

/// Which kind of item a tagged value list belongs to: the annotation tags differ.
#[derive(Debug, Clone, Copy)]
pub(super) enum Holder {
    Class,
    Field,
    Method,
}

impl Holder {
    pub(super) fn annotation_tag(self, kind: AnnotationKind) -> u8 {
        match (self, kind) {
            (Holder::Class | Holder::Field | Holder::Method, AnnotationKind::Runtime) => 0x03,
            (Holder::Class | Holder::Field, AnnotationKind::Plain) => 0x04,
            (Holder::Class | Holder::Field, AnnotationKind::RuntimeType) => 0x05,
            (Holder::Class | Holder::Field, AnnotationKind::Type) => 0x06,
            (Holder::Method, AnnotationKind::Plain) => 0x06,
            (Holder::Method, AnnotationKind::Type) => 0x08,
            (Holder::Method, AnnotationKind::RuntimeType) => 0x09,
        }
    }

    /// The annotations of one holder in the order they are written: the
    /// official writer goes kind by kind, in ascending tag order.
    pub(super) fn ordered(self, annotations: &[AbcAnnotation]) -> Vec<&AbcAnnotation> {
        let mut ordered: Vec<&AbcAnnotation> = annotations.iter().collect();
        ordered.sort_by_key(|annotation| self.annotation_tag(annotation.kind));
        ordered
    }
}
