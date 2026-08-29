use rustc_data_structures::fx::FxHashMap;
use rustc_hir::{
    def_id::{DefId, LocalDefId},
    intravisit,
    Block, BodyId, HirId, Impl, ItemKind,
};
use rustc_middle::ty::{Ty, TyCtxt, TyKind};
use rustc_span::Span;

/// Maps `HirId` of a type to `BodyId` of related impls.
/// Free-standing (top level) functions and default trait impls have `None` as a key.
pub type RelatedItemMap = FxHashMap<Option<HirId>, Vec<(BodyId, Span)>>;

/// Creates `AdtItemMap` with the given HIR map.
/// You might want to use `RudraCtxt`'s `related_item_cache` field instead of
/// directly using this collector.
pub struct RelatedFnCollector<'tcx> {
    _tcx: TyCtxt<'tcx>,
}

impl<'tcx> RelatedFnCollector<'tcx> {
    pub fn collect(tcx: TyCtxt<'tcx>) -> RelatedItemMap {
        let mut hash_map = RelatedItemMap::default();

        for item_id in tcx.hir_crate_items(()).free_items() {
            let item = tcx.hir_item(item_id);
            match &item.kind {
                ItemKind::Impl(Impl {
                    self_ty,
                    items: impl_items,
                    ..
                }) => {
                    let key = Some(self_ty.hir_id);
                    let entry = hash_map.entry(key).or_insert(Vec::new());
                    for &impl_item_id in *impl_items {
                        let impl_item = tcx.hir_impl_item(impl_item_id);
                        if let rustc_hir::ImplItemKind::Fn(_sig, body_id) = impl_item.kind {
                            entry.push((body_id, impl_item.span));
                        }
                    }
                }
                // Free-standing (top level) functions and default trait impls have `None` as a key.
                ItemKind::Trait(.., trait_items) => {
                    let key = None;
                    let entry = hash_map.entry(key).or_insert(Vec::new());
                    for &trait_item_id in *trait_items {
                        let trait_item = tcx.hir_trait_item(trait_item_id);
                        if let rustc_hir::TraitItemKind::Fn(_sig, rustc_hir::TraitFn::Provided(body_id)) = trait_item.kind {
                            entry.push((body_id, trait_item.span));
                        }
                    }
                }
                ItemKind::Fn { body, .. } => {
                    let key = None;
                    let entry = hash_map.entry(key).or_insert(Vec::new());
                    entry.push((*body, item.span));
                }
                _ => (),
            }
        }

        hash_map
    }
}

pub struct ContainsUnsafe<'tcx> {
    tcx: TyCtxt<'tcx>,
    contains_unsafe: bool,
}

impl<'tcx> ContainsUnsafe<'tcx> {
    /// Given a `BodyId`, returns if the corresponding body contains unsafe code in it.
    /// Note that it only checks the function body, so this function will return false for
    /// body ids of functions that are defined as unsafe.
    pub fn contains_unsafe(tcx: TyCtxt<'tcx>, body_id: BodyId) -> bool {
        use intravisit::Visitor;

        let mut visitor = ContainsUnsafe {
            tcx,
            contains_unsafe: false,
        };

        let body = visitor.tcx.hir_body(body_id);
        visitor.visit_body(body);

        visitor.contains_unsafe
    }
}

impl<'tcx> intravisit::Visitor<'tcx> for ContainsUnsafe<'tcx> {
    type NestedFilter = rustc_middle::hir::nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_block(&mut self, block: &'tcx Block<'tcx>) {
        use rustc_hir::BlockCheckMode;
        if let BlockCheckMode::UnsafeBlock(_unsafe_source) = block.rules {
            self.contains_unsafe = true;
        }
        intravisit::walk_block(self, block);
    }
}

/// (`DefId` of ADT) => Vec<(HirId of relevant impl block, impl_self_ty)>
/// We use this map to quickly access associated impl blocks per ADT.
/// `impl_self_ty` in the return value may differ from `tcx.type_of(ADT.DefID)`,
/// as different instantiations of the same ADT are distinct `Ty`s.
/// (e.g. Foo<i32, i64>, Foo<String, i32>)
pub type AdtImplMap<'tcx> = FxHashMap<DefId, Vec<(LocalDefId, Ty<'tcx>)>>;

/// Create & initialize `AdtImplMap`.
/// `AdtImplMap` is initialized before analysis of each crate,
/// avoiding quadratic complexity of scanning all impl blocks for each ADT.
pub fn create_adt_impl_map<'tcx>(tcx: TyCtxt<'tcx>) -> AdtImplMap<'tcx> {
    let mut map = FxHashMap::default();

    for item_id in tcx.hir_crate_items(()).free_items() {
        let item = tcx.hir_item(item_id);
        if let ItemKind::Impl(Impl { self_ty: _, .. }) = item.kind {
            // `Self` type of the given impl block.
            let impl_self_ty = tcx.type_of(item.owner_id.def_id).instantiate_identity();

            if let TyKind::Adt(impl_self_adt_def, _impl_args) = impl_self_ty.kind() {
                map.entry(impl_self_adt_def.did())
                    .or_insert_with(Vec::new)
                    .push((item.owner_id.def_id, impl_self_ty));
            }
        }
    }

    map
}
