/*!
```rudra-test
test_type = "normal"
expected_analyzers = ["SendSyncVariance"]
```
!*/

struct Atom<P>(P);
unsafe impl<P: Ord> Send for Atom<P> {}

// Instantiation harness: the wild `unsafe impl<P: Ord> Send` is the whole
// case, but P is generic and a plain lib build monomorphizes nothing.
// Atom<Rc<i32>> is the exact unsound instantiation (Rc is Ord but not
// Send); the concrete use forces the impl to be instantiated so the
// variance problem is reachable.  Test-only; the unsafe impl above is
// unchanged.
#[cfg(test)]
mod instantiate {
    use super::Atom;

    #[test]
    fn exercise_wild_send_instantiation() {
        let _ = Atom(std::rc::Rc::new(1i32));
    }
}
