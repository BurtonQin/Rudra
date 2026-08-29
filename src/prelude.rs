use rustc_hir::{
    def::Res,
    def_id::DefId,
    Expr, ExprKind, Safety,
};
use rustc_middle::ty::{self, Ty, TyCtxt};

use rustc_span::Symbol;
use snafu::{Backtrace, Snafu};
pub use snafu::{Error, ErrorCompat, IntoError, OptionExt, ResultExt};

pub use crate::analysis::{AnalysisError, AnalysisErrorKind, AnalysisResult};
pub use crate::context::RudraCtxt;
pub use crate::report::rudra_report;

#[derive(Debug, Snafu)]
pub enum ExtError {
    NonFunctionType { backtrace: Backtrace },
    InvalidOwner { backtrace: Backtrace },
    UnsupportedCall { backtrace: Backtrace },
    UnhandledCall { backtrace: Backtrace },
}

impl AnalysisError for ExtError {
    fn kind(&self) -> AnalysisErrorKind {
        use ExtError::*;
        match self {
            NonFunctionType { .. } => AnalysisErrorKind::Unreachable,
            InvalidOwner { .. } => AnalysisErrorKind::Unreachable,
            UnsupportedCall { .. } => AnalysisErrorKind::OutOfScope,
            UnhandledCall { .. } => AnalysisErrorKind::Unimplemented,
        }
    }
}

pub trait TyCtxtExt<'tcx> {
    fn ext(self) -> TyCtxtExtension<'tcx>;
}

impl<'tcx> TyCtxtExt<'tcx> for TyCtxt<'tcx> {
    fn ext(self) -> TyCtxtExtension<'tcx> {
        TyCtxtExtension { tcx: self }
    }
}

#[derive(Clone, Copy)]
pub struct TyCtxtExtension<'tcx> {
    tcx: TyCtxt<'tcx>,
}

impl<'tcx> TyCtxtExtension<'tcx> {
    pub fn fn_type_unsafety(self, ty: Ty<'tcx>) -> AnalysisResult<'tcx, Safety> {
        match ty.kind() {
            ty::FnDef(..) | ty::FnPtr(..) => {
                let sig = ty.fn_sig(self.tcx);
                Ok(sig.safety())
            }
            ty::Closure(_def_id, args) => {
                let sig = args.as_closure().sig();
                Ok(sig.safety())
            }
            _ => convert!(NonFunctionType.fail()),
        }
    }

    /// Checks if the given def_id matches the path string.
    /// Prefer [`crate::paths::PathSet`] when comparing a single definition against multiple paths.
    pub fn match_def_path(self, def_id: DefId, syms: &[&str]) -> bool {
        let syms = syms
            .iter()
            .map(|p| Symbol::intern(p))
            .collect::<Vec<Symbol>>();

        let names = self.get_def_path(def_id);
        names.len() == syms.len() && names.into_iter().zip(syms.iter()).all(|(a, &b)| a == b)
    }

    pub fn get_def_path(&self, def_id: DefId) -> Vec<Symbol> {
        let mut path = vec![self.tcx.crate_name(def_id.krate)];
        for disambiguated_data in self.tcx.def_path(def_id).data {
            if let Some(name) = disambiguated_data.data.get_opt_name() {
                path.push(name);
            }
        }
        path
    }
}

pub trait ExprExt<'tcx> {
    fn ext(self) -> ExprExtension<'tcx>;
}

impl<'tcx> ExprExt<'tcx> for &'tcx Expr<'tcx> {
    fn ext(self) -> ExprExtension<'tcx> {
        ExprExtension { expr: self }
    }
}

#[derive(Clone, Copy)]
pub struct ExprExtension<'tcx> {
    expr: &'tcx Expr<'tcx>,
}

impl<'tcx> ExprExtension<'tcx> {
    /// Returns `Some(def_id)` if expression is a function
    /// Returns `None` if expression is not a function or error happens
    pub fn as_fn_def_id(self, tcx: TyCtxt<'tcx>) -> Option<DefId> {
        if !tcx.has_typeck_results(self.expr.hir_id.owner.def_id) {
            log_err!(InvalidOwner);
            return None;
        }

        let typeck_tables = tcx.typeck(self.expr.hir_id.owner.def_id);
        trace!("as_fn_def_id() on {:?}", self.expr);
        match self.expr.kind {
            ExprKind::Call(path_expr, _args) => match &path_expr.kind {
                ExprKind::Path(path) => {
                    let res = typeck_tables.qpath_res(path, path_expr.hir_id);
                    match res {
                        Res::Def(_def_kind, def_id) => Some(def_id),
                        _ => {
                            log_err!(UnhandledCall);
                            None
                        }
                    }
                }
                ExprKind::Field(..) => {
                    // Example: (self.0)(self.1, self.2);
                    log_err!(UnsupportedCall);
                    None
                }
                _ => {
                    log_err!(UnhandledCall);
                    None
                }
            },
            ExprKind::MethodCall(..) => typeck_tables.type_dependent_def_id(self.expr.hir_id),
            // expected failure, silent
            _ => None,
        }
    }
}
