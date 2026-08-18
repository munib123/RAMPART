# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 856_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `856_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 117-157 of the vulnerable file.


void HeaderTable::removeLast() {
  auto t = tail();
  refset_.erase(t);
  skippedRefs_.erase(t);
  // remove the first element from the names index
  auto names_it = names_.find(table_[t].name);
  DCHECK(names_it != names_.end());
  list<uint32_t> &ilist = names_it->second;
  DCHECK(ilist.front() ==t);
  ilist.pop_front();
  // remove the name if there are no indices associated with it
  if (ilist.empty()) {
    names_.erase(names_it);
  }
  bytes_ -= table_[t].bytes();
  --size_;
}

void HeaderTable::setCapacity(uint32_t capacity) {
  auto oldCapacity = capacity_;
  capacity_ = capacity;
  if (capacity_ <= oldCapacity) {
    evict(0);
  } else {
    auto oldTail = tail();
    auto oldLength = table_.size();
    uint32_t newLength = (capacity_ >> 5) + 1;
    table_.resize(newLength);
    if (size_ > 0 && oldTail > head_) {
      // the list wrapped around, need to move oldTail..oldLength to the end of
      // the now-larger table_
      std::copy(table_.begin() + oldTail, table_.begin() + oldLength,
                table_.begin() + newLength - (oldLength - oldTail));
      // Update the names indecies that pointed to the old range
      for (auto& names_it: names_) {
        for (auto& idx: names_it.second) {
          if (idx >= oldTail) {
            DCHECK_LT(idx + (table_.size() - oldLength), table_.size());
            idx += (table_.size() - oldLength);
          } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,30 +134,42 @@
 }
 
 void HeaderTable::setCapacity(uint32_t capacity) {
+  // TODO: ddmello - the below is a little dangerous as we update the
+  // capacity right away.  Some properties of the class utilize that variable
+  // and so might be better to refactor and update capacity at the end of the
+  // method (and update other methods)
   auto oldCapacity = capacity_;
   capacity_ = capacity;
-  if (capacity_ <= oldCapacity) {
+  if (capacity_ == oldCapacity) {
+    return;
+  } else if (capacity_ < oldCapacity) {
+    // NOTE: currently no actual resizing is performed...
     evict(0);
   } else {
-    auto oldTail = tail();
-    auto oldLength = table_.size();
+    // NOTE: due to the above lack of resizing, we must determine whether a
+    // resize is actually appropriate (to handle cases where the underlying
+    // vector is still >= to the size related to the new capacity requested)
     uint32_t newLength = (capacity_ >> 5) + 1;
-    table_.resize(newLength);
-    if (size_ > 0 && oldTail > head_) {
-      // the list wrapped around, need to move oldTail..oldLength to the end of
-      // the now-larger table_
-      std::copy(table_.begin() + oldTail, table_.begin() + oldLength,
-                table_.begin() + newLength - (oldLength - oldTail));
-      // Update the names indecies that pointed to the old range
-      for (auto& names_it: names_) {
-        for (auto& idx: names_it.second) {
-          if (idx >= oldTail) {
-            DCHECK_LT(idx + (table_.size() - oldLength), table_.size());
-            idx += (table_.size() - oldLength);
-          } else {
-            // remaining indecies in the list were smaller than oldTail, so
-            // should be indexed from 0
-            break;
+    if (newLength > table_.size()) {
+      auto oldTail = tail();
+      auto oldLength = table_.size();
+      table_.resize(newLength);
+      if (size_ > 0 && oldTail > head_) {
+        // the list wrapped around, need to move oldTail..oldLength to the end
+        // of the now-larger table_
+        std::copy(table_.begin() + oldTail, table_.begin() + oldLength,
+                  table_.begin() + newLength - (oldLength - oldTail));
+        // Update the names indecies that pointed to the old range
+        for (auto& names_it: names_) {
+          for (auto& idx: names_it.second) {
+            if (idx >= oldTail) {
+              DCHECK_LT(idx + (table_.size() - oldLength), table_.size());
+              idx += (table_.size() - oldLength);
+            } else {
+              // remaining indecies in the list were smaller than oldTail, so
+              // should be indexed from 0
+              break;
+            }
           }
         }
       }
```
