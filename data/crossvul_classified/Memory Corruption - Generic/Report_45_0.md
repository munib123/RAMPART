# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in rust
**Pair ID:** 45_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `45_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```rust
Lines 541-581 of the vulnerable file.

    ///
    /// Panics if the new capacity overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::VecDeque;
    ///
    /// let mut buf: VecDeque<i32> = vec![1].into_iter().collect();
    /// buf.reserve(10);
    /// assert!(buf.capacity() >= 11);
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    pub fn reserve(&mut self, additional: usize) {
        let old_cap = self.cap();
        let used_cap = self.len() + 1;
        let new_cap = used_cap.checked_add(additional)
            .and_then(|needed_cap| needed_cap.checked_next_power_of_two())
            .expect("capacity overflow");

        if new_cap > self.capacity() {
            self.buf.reserve_exact(used_cap, new_cap - used_cap);
            unsafe {
                self.handle_cap_increase(old_cap);
            }
        }
    }

    /// Shrinks the capacity of the `VecDeque` as much as possible.
    ///
    /// It will drop down as close as possible to the length but the allocator may still inform the
    /// `VecDeque` that there is space for a few more elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::VecDeque;
    ///
    /// let mut buf = VecDeque::with_capacity(15);
    /// buf.extend(0..4);
    /// assert_eq!(buf.capacity(), 15);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -558,7 +558,7 @@
             .and_then(|needed_cap| needed_cap.checked_next_power_of_two())
             .expect("capacity overflow");
 
-        if new_cap > self.capacity() {
+        if new_cap > old_cap {
             self.buf.reserve_exact(used_cap, new_cap - used_cap);
             unsafe {
                 self.handle_cap_increase(old_cap);
```
