/*!
```rudra-test
test_type = "normal"
expected_analyzers = ["UnsafeDataflow"]
```
!*/

use std::fmt::Debug;

fn test_order_unsafe<I: Iterator<Item = impl Debug>>(mut iter: I) {
    unsafe {
        std::ptr::read(&Box::new(1234) as *const _);
    }
    println!("{:?}", iter.next());
}

// Instantiation harness: the function above is generic and would never be
// monomorphized by a plain lib build, leaving Lockbud with 0 analyzable
// instances.  A concrete use forces monomorphization so the unsafe→panic
// pattern is reachable.  Test-only; the bug pattern above is unchanged.
#[cfg(test)]
mod instantiate {
    use super::test_order_unsafe;

    #[test]
    fn exercise_generic_path() {
        test_order_unsafe(vec![1i32, 2, 3].into_iter());
    }
}
