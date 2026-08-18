# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 3649_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3649_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 174-214 of the vulnerable file.

      str_ = s;
      on_heap_ = true;
    }
  }


  void Reset() {
    if (on_heap_) {
      delete[] str_;
      on_heap_ = false;
    }

    str_ = NULL;
    size_ = 0;
  }


  void Update(const char* str, size_t size) {
    if (str_ == NULL)
      str_ = str;
    else if (on_heap_ || str_ + size != str) {
      // Non-consecutive input, make a copy on the heap.
      // TODO Use slab allocation, O(n) allocs is bad.
      char* s = new char[size_ + size];
      memcpy(s, str_, size_);
      memcpy(s + size_, str, size);

      if (on_heap_)
        delete[] str_;
      else
        on_heap_ = true;

      str_ = s;
    }
    size_ += size;
  }


  Handle<String> ToString() const {
    if (str_)
      return String::New(str_, size_);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,7 +191,7 @@
   void Update(const char* str, size_t size) {
     if (str_ == NULL)
       str_ = str;
-    else if (on_heap_ || str_ + size != str) {
+    else if (on_heap_ || str_ + size_ != str) {
       // Non-consecutive input, make a copy on the heap.
       // TODO Use slab allocation, O(n) allocs is bad.
       char* s = new char[size_ + size];
```
