# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4909_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4909_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 18-58 of the vulnerable file.


#include <algorithm>

#include "sfntly/port/exception_type.h"

namespace sfntly {

const int32_t ByteArray::COPY_BUFFER_SIZE = 8192;

ByteArray::~ByteArray() {}

int32_t ByteArray::Length() { return filled_length_; }
int32_t ByteArray::Size() { return storage_length_; }

int32_t ByteArray::SetFilledLength(int32_t filled_length) {
  filled_length_ = std::min<int32_t>(filled_length, storage_length_);
  return filled_length_;
}

int32_t ByteArray::Get(int32_t index) {
  return InternalGet(index) & 0xff;
}

int32_t ByteArray::Get(int32_t index, ByteVector* b) {
  assert(b);
  return Get(index, &((*b)[0]), 0, b->size());
}

int32_t ByteArray::Get(int32_t index,
                       byte_t* b,
                       int32_t offset,
                       int32_t length) {
  assert(b);
  if (index < 0 || index >= filled_length_) {
    return 0;
  }
  int32_t actual_length = std::min<int32_t>(length, filled_length_ - index);
  return InternalGet(index, b, offset, actual_length);
}

void ByteArray::Put(int32_t index, byte_t b) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,8 @@
 }
 
 int32_t ByteArray::Get(int32_t index) {
+  if (index < 0 || index >= Length())
+    return -1;
   return InternalGet(index) & 0xff;
 }
 
```
