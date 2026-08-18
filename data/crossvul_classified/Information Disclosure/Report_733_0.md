# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in rust
**Pair ID:** 733_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** rust
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `733_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```rust
Lines 1971-2011 of the vulnerable file.

    (head.wrapping_sub(tail)) & (size - 1)
}

/// An iterator over the elements of a `VecDeque`.
///
/// This `struct` is created by the [`iter`] method on [`VecDeque`]. See its
/// documentation for more.
///
/// [`iter`]: struct.VecDeque.html#method.iter
/// [`VecDeque`]: struct.VecDeque.html
#[stable(feature = "rust1", since = "1.0.0")]
pub struct Iter<'a, T: 'a> {
    ring: &'a [T],
    tail: usize,
    head: usize,
}

#[stable(feature = "collection_debug", since = "1.17.0")]
impl<'a, T: 'a + fmt::Debug> fmt::Debug for Iter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Iter")
         .field(&self.ring)
         .field(&self.tail)
         .field(&self.head)
         .finish()
    }
}

// FIXME(#26925) Remove in favor of `#[derive(Clone)]`
#[stable(feature = "rust1", since = "1.0.0")]
impl<'a, T> Clone for Iter<'a, T> {
    fn clone(&self) -> Iter<'a, T> {
        Iter {
            ring: self.ring,
            tail: self.tail,
            head: self.head,
        }
    }
}

#[stable(feature = "rust1", since = "1.0.0")]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1988,11 +1988,11 @@
 #[stable(feature = "collection_debug", since = "1.17.0")]
 impl<'a, T: 'a + fmt::Debug> fmt::Debug for Iter<'a, T> {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        let (front, back) = RingSlices::ring_slices(self.ring, self.head, self.tail);
         f.debug_tuple("Iter")
-         .field(&self.ring)
-         .field(&self.tail)
-         .field(&self.head)
-         .finish()
+            .field(&front)
+            .field(&back)
+            .finish()
     }
 }
 
@@ -2085,11 +2085,11 @@
 #[stable(feature = "collection_debug", since = "1.17.0")]
 impl<'a, T: 'a + fmt::Debug> fmt::Debug for IterMut<'a, T> {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        let (front, back) = RingSlices::ring_slices(&*self.ring, self.head, self.tail);
         f.debug_tuple("IterMut")
-         .field(&self.ring)
-         .field(&self.tail)
-         .field(&self.head)
-         .finish()
+            .field(&front)
+            .field(&back)
+            .finish()
     }
 }
 
```
