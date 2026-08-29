//! Unsafe Send/Sync impl detector (relaxed)
#![allow(dead_code)]

use super::*;

// We may not use the relaxed versions at all,
// but keeping them alive just in case..
impl<'tcx> SendSyncVarianceChecker<'tcx> {
    /// Detect suspicious `Send` with relaxed rules.
    /// Report only if all generic parameters of `impl Send` aren't `Send`.
    fn suspicious_send_relaxed(
        &self,
        hir_id: HirId,
        send_trait_def_id: DefId,
        sync_trait_def_id: DefId,
    ) -> bool {
        let tcx = self.rcx.tcx();
        if_chain! {
            if let rustc_hir::Node::Item(item) = tcx.hir_node(hir_id);
            if let ItemKind::Impl(Impl {
                ref generics,
                ..
            }) = item.kind;
            if let Some(trait_ref) = tcx.impl_opt_trait_ref(item.owner_id.def_id.to_def_id());
            if trait_ref.skip_binder().def_id == send_trait_def_id;
            then {
                // If `impl Send` doesn't involve generic parameters, don't catch it.
                if generics.params.is_empty() {
                    return false;
                }

                // Inspect immediate trait bounds on generic parameters
                if self.trait_in_imm_relaxed(
                    &[send_trait_def_id, sync_trait_def_id],
                    generics
                ) {
                    return false;
                }

                // Inspect trait bounds in where clauses
                return !self.trait_in_where_relaxed(
                    &[send_trait_def_id, sync_trait_def_id],
                    generics.predicates
                );
            }
        }
        false
    }

    /// Detect suspicious Sync with relaxed rules.
    /// Report only if all generic parameters of `impl Sync` aren't Sync.
    fn suspicious_sync_relaxed(
        &self,
        // HirId of the `Impl Sync` item
        hir_id: HirId,
        sync_trait_def_id: DefId,
    ) -> bool {
        let tcx = self.rcx.tcx();
        if_chain! {
            if let rustc_hir::Node::Item(item) = tcx.hir_node(hir_id);
            if let ItemKind::Impl(Impl {
                ref generics,
                ..
            }) = item.kind;
            if let Some(trait_ref) = tcx.impl_opt_trait_ref(item.owner_id.def_id.to_def_id());
            if trait_ref.skip_binder().def_id == sync_trait_def_id;
            then {
                // If `impl Sync` doesn't involve generic parameters, don't catch it.
                if generics.params.is_empty() {
                    return false;
                }

                // Inspect immediate trait bounds on generic parameters
                if self.trait_in_imm_relaxed(
                   &[sync_trait_def_id],
                   generics
                ) {
                   return false;
                }

                return !self.trait_in_where_relaxed(
                    &[sync_trait_def_id],
                    generics.predicates
                );
            }
        }
        false
    }

    fn trait_in_imm_relaxed(
        &self,
        target_trait_def_ids: &[DefId],
        generics: &rustc_hir::Generics,
    ) -> bool {
        for predicate in generics.predicates {
            if let rustc_hir::WherePredicateKind::BoundPredicate(bp) = &predicate.kind {
                for bound in bp.bounds {
                    if let GenericBound::Trait(x, ..) = bound {
                        if let Some(def_id) = x.trait_ref.path.res.opt_def_id() {
                            if target_trait_def_ids.contains(&def_id) {
                                return true;
                            }

                            // Check super-traits
                            for p in self.rcx.tcx().explicit_super_predicates_of(def_id).skip_binder() {
                                if let ty::ClauseKind::Trait(x) = p.0.kind().skip_binder() {
                                    if target_trait_def_ids.contains(&x.trait_ref.def_id) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn trait_in_where_relaxed(
        &self,
        target_trait_def_ids: &[DefId],
        where_predicates: &[WherePredicate],
    ) -> bool {
        for where_predicate in where_predicates {
            if let rustc_hir::WherePredicateKind::BoundPredicate(bp) = &where_predicate.kind {
                for bound in bp.bounds {
                    if let GenericBound::Trait(y, ..) = bound {
                        if let Some(def_id) = y.trait_ref.path.res.opt_def_id() {
                            if target_trait_def_ids.contains(&def_id) {
                                return true;
                            }

                            for p in self.rcx.tcx().explicit_super_predicates_of(def_id).skip_binder() {
                                if let ty::ClauseKind::Trait(z) = p.0.kind().skip_binder() {
                                    if target_trait_def_ids.contains(&z.trait_ref.def_id) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }
}
