# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1029_5
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_5`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1-39 of the vulnerable file.

#pragma once

#include <array>
#include <cstdint>
#include <list>
#include <memory>
#include <string>

#include "envoy/http/header_map.h"

#include "common/common/non_copyable.h"
#include "common/http/headers.h"

namespace Envoy {
namespace Http {

/**
 * These are definitions of all of the inline header access functions described inside header_map.h
 */
#define DEFINE_INLINE_HEADER_FUNCS(name)                                                           \
public:                                                                                            \
  const HeaderEntry* name() const override { return inline_headers_.name##_; }                     \
  HeaderEntry* name() override { return inline_headers_.name##_; }                                 \
  HeaderEntry& insert##name() override {                                                           \
    return maybeCreateInline(&inline_headers_.name##_, Headers::get().name);                       \
  }                                                                                                \
  void remove##name() override { removeInline(&inline_headers_.name##_); }

#define DEFINE_INLINE_HEADER_STRUCT(name) HeaderEntryImpl* name##_;

/**
 * Implementation of Http::HeaderMap. This is heavily optimized for performance. Roughly, when
 * headers are added to the map, we do a hash lookup to see if it's one of the O(1) headers.
 * If it is, we store a reference to it that can be accessed later directly. Most high performance
 * paths use O(1) direct access. In general, we try to copy as little as possible and allocate as
 * little as possible in any of the paths.
 */
class HeaderMapImpl : public HeaderMap, NonCopyable {
public:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,12 +16,21 @@
 
 /**
  * These are definitions of all of the inline header access functions described inside header_map.h
+ *
+ * When a non-const reference or pointer to a HeaderEntry is returned, the internal byte size count
+ * will be cleared, since HeaderMap will no longer be able to accurately update the size of that
+ * HeaderEntry.
+ * TODO(asraa): Remove functions with a non-const HeaderEntry return value.
  */
 #define DEFINE_INLINE_HEADER_FUNCS(name)                                                           \
 public:                                                                                            \
   const HeaderEntry* name() const override { return inline_headers_.name##_; }                     \
-  HeaderEntry* name() override { return inline_headers_.name##_; }                                 \
+  HeaderEntry* name() override {                                                                   \
+    cached_byte_size_.reset();                                                                     \
+    return inline_headers_.name##_;                                                                \
+  }                                                                                                \
   HeaderEntry& insert##name() override {                                                           \
+    cached_byte_size_.reset();                                                                     \
     return maybeCreateInline(&inline_headers_.name##_, Headers::get().name);                       \
   }                                                                                                \
   void remove##name() override { removeInline(&inline_headers_.name##_); }
@@ -43,7 +52,7 @@
    * @param header the header to append to.
    * @param data to append to the header.
    */
-  static void appendToHeader(HeaderString& header, absl::string_view data);
+  static uint64_t appendToHeader(HeaderString& header, absl::string_view data);
 
   HeaderMapImpl();
   explicit HeaderMapImpl(
@@ -71,7 +80,9 @@
   void addCopy(const LowerCaseString& key, const std::string& value) override;
   void setReference(const LowerCaseString& key, const std::string& value) override;
   void setReferenceKey(const LowerCaseString& key, const std::string& value) override;
-  uint64_t byteSize() const override;
+  absl::optional<uint64_t> byteSize() const override;
+  uint64_t refreshByteSize() override;
+  uint64_t byteSizeInternal() const override;
   const HeaderEntry* get(const LowerCaseString& key) const override;
   HeaderEntry* get(const LowerCaseString& key) override;
   void iterate(ConstIterateCb cb, void* context) const override;
@@ -195,10 +206,16 @@
   HeaderEntryImpl* getExistingInline(absl::string_view key);
 
   void removeInline(HeaderEntryImpl** entry);
+  void addSize(uint64_t size);
+  void subtractSize(uint64_t size);
 
   AllInlineHeaders inline_headers_;
   HeaderList headers_;
 
+  // When present, this holds the internal byte size of the HeaderMap. The value is removed once an
+  // inline header entry is accessed and updated when refreshByteSize() is called.
+  absl::optional<uint64_t> cached_byte_size_ = 0;
+
   ALL_INLINE_HEADERS(DEFINE_INLINE_HEADER_FUNCS)
 };
 
```
