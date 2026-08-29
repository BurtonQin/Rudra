//! A various utility iterators that iterate over Rustc internal items.
//! Many of these internally use `Vec`. Directly returning that `Vec` might be
//! more performant, but we are intentionally trying to hide the implementation
//! detail here.

use rustc_hir::def_id::{DefId, LocalDefId};

use crate::prelude::*;

/// Given a trait `DefId`, this iterator returns `HirId` of all local impl blocks
/// that implements that trait.
pub struct LocalTraitIter {
    inner: std::vec::IntoIter<LocalDefId>,
}

impl LocalTraitIter {
    pub fn new<'tcx>(rcx: RudraCtxt<'tcx>, trait_def_id: DefId) -> Self {
        let mut impl_id_vec = Vec::new();
        let tcx = rcx.tcx();
        for item_id in tcx.hir_crate_items(()).free_items() {
            let item = tcx.hir_item(item_id);
            if let rustc_hir::ItemKind::Impl(..) = item.kind {
                if let Some(trait_ref) = tcx.impl_opt_trait_ref(item.owner_id.def_id.to_def_id()) {
                    if trait_ref.skip_binder().def_id == trait_def_id {
                        impl_id_vec.push(item.owner_id.def_id);
                    }
                }
            }
        }
        LocalTraitIter {
            inner: impl_id_vec.into_iter(),
        }
    }
}

impl Iterator for LocalTraitIter {
    type Item = LocalDefId;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
