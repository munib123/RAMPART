# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 1029_4
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_4`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 278-318 of the vulnerable file.

#define INLINE_HEADER_STATIC_MAP_ENTRY(name)                                                       \
  add(Headers::get().name.get().c_str(), [](HeaderMapImpl& h) -> StaticLookupResponse {            \
    return {&h.inline_headers_.name##_, &Headers::get().name};                                     \
  });

/**
 * This is the static lookup table that is used to determine whether a header is one of the O(1)
 * headers. This uses a trie for lookup time at most equal to the size of the incoming string.
 */
struct HeaderMapImpl::StaticLookupTable : public TrieLookupTable<EntryCb> {
  StaticLookupTable() {
    ALL_INLINE_HEADERS(INLINE_HEADER_STATIC_MAP_ENTRY)

    // Special case where we map a legacy host header to :authority.
    add(Headers::get().HostLegacy.get().c_str(), [](HeaderMapImpl& h) -> StaticLookupResponse {
      return {&h.inline_headers_.Host_, &Headers::get().Host};
    });
  }
};

void HeaderMapImpl::appendToHeader(HeaderString& header, absl::string_view data) {
  if (data.empty()) {
    return;
  }
  if (!header.empty()) {
    header.append(",", 1);
  }
  header.append(data.data(), data.size());
}

HeaderMapImpl::HeaderMapImpl() { memset(&inline_headers_, 0, sizeof(inline_headers_)); }

HeaderMapImpl::HeaderMapImpl(
    const std::initializer_list<std::pair<LowerCaseString, std::string>>& values)
    : HeaderMapImpl() {
  for (auto& value : values) {
    HeaderString key_string;
    key_string.setCopy(value.first.get().c_str(), value.first.get().size());
    HeaderString value_string;
    value_string.setCopy(value.second.c_str(), value.second.size());
    addViaMove(std::move(key_string), std::move(value_string));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,14 +295,17 @@
   }
 };
 
-void HeaderMapImpl::appendToHeader(HeaderString& header, absl::string_view data) {
+uint64_t HeaderMapImpl::appendToHeader(HeaderString& header, absl::string_view data) {
   if (data.empty()) {
-    return;
-  }
+    return 0;
+  }
+  uint64_t byte_size = 0;
   if (!header.empty()) {
     header.append(",", 1);
+    byte_size += 1;
   }
   header.append(data.data(), data.size());
+  return data.size() + byte_size;
 }
 
 HeaderMapImpl::HeaderMapImpl() { memset(&inline_headers_, 0, sizeof(inline_headers_)); }
@@ -319,6 +322,20 @@
   }
 }
 
+void HeaderMapImpl::addSize(uint64_t size) {
+  // Adds size to cached_byte_size_ if it exists.
+  if (cached_byte_size_.has_value()) {
+    cached_byte_size_.value() += size;
+  }
+}
+
+void HeaderMapImpl::subtractSize(uint64_t size) {
+  if (cached_byte_size_.has_value()) {
+    ASSERT(cached_byte_size_ >= size);
+    cached_byte_size_.value() -= size;
+  }
+}
+
 void HeaderMapImpl::copyFrom(const HeaderMap& header_map) {
   header_map.iterate(
       [](const HeaderEntry& header, void* context) -> HeaderMap::Iterate {
@@ -359,10 +376,13 @@
     if (*ref_lookup_response.entry_ == nullptr) {
       maybeCreateInline(ref_lookup_response.entry_, *ref_lookup_response.key_, std::move(value));
     } else {
-      appendToHeader((*ref_lookup_response.entry_)->value(), value.getStringView());
+      const uint64_t added_size =
+          appendToHeader((*ref_lookup_response.entry_)->value(), value.getStringView());
+      addSize(added_size);
       value.clear();
     }
   } else {
+    addSize(key.size() + value.size());
     std::list<HeaderEntryImpl>::iterator i = headers_.insert(std::move(key), std::move(value));
     i->entry_ = i;
   }
@@ -373,7 +393,8 @@
   // the existing value.
   auto* entry = getExistingInline(key.getStringView());
   if (entry != nullptr) {
-    appendToHeader(entry->value(), value.getStringView());
+    const uint64_t added_size = appendToHeader(entry->value(), value.getStringView());
+    addSize(added_size);
     key.clear();
     value.clear();
   } else {
@@ -408,7 +429,8 @@
   if (entry != nullptr) {
     char buf[32];
     StringUtil::itoa(buf, sizeof(buf), value);
-    appendToHeader(entry->value(), buf);
+    const uint64_t added_size = appendToHeader(entry->value(), buf);
+    addSize(added_size);
     return;
   }
   HeaderString new_key;
@@ -423,7 +445,8 @@
 void HeaderMapImpl::addCopy(const LowerCaseString& key, const std::string& value) {
   auto* entry = getExistingInline(key.get());
   if (entry != nullptr) {
-    appendToHeader(entry->value(), value);
+    const uint64_t added_size = appendToHeader(entry->value(), value);
+    addSize(added_size);
     return;
   }
   HeaderString new_key;
@@ -451,13 +474,24 @@
   ASSERT(new_value.empty()); // NOLINT(bugprone-use-after-move)
 }
 
-uint64_t HeaderMapImpl::byteSize() const {
+absl::optional<uint64_t> HeaderMapImpl::byteSize() const { return cached_byte_size_; }
+
+uint64_t HeaderMapImpl::refreshByteSize() {
+  if (!cached_byte_size_.has_value()) {
+    // In this case, the cached byte size is not valid, and the byte size is computed via an
+    // iteration over the HeaderMap. The cached byte size is updated.
+    cached_byte_size_ = byteSizeInternal();
+  }
+  return cached_byte_size_.value();
+}
+
+uint64_t HeaderMapImpl::byteSizeInternal() const {
+  // Computes the total byte size by summing the byte size of the keys and values.
   uint64_t byte_size = 0;
   for (const HeaderEntryImpl& header : headers_) {
     byte_size += header.key().size();
     byte_size += header.value().size();
   }
-
   return byte_size;
 }
 
@@ -474,6 +508,7 @@
 HeaderEntry* HeaderMapImpl::get(const LowerCaseString& key) {
   for (HeaderEntryImpl& header : headers_) {
     if (header.key() == key.get().c_str()) {
+      cached_byte_size_.reset();
       return &header;
     }
   }
@@ -528,6 +563,7 @@
   } else {
     for (auto i = headers_.begin(); i != headers_.end();) {
       if (i->key() == key.get().c_str()) {
+        subtractSize(i->key().size() + i->value().size());
         i = headers_.erase(i);
       } else {
         ++i;
@@ -537,7 +573,7 @@
 }
 
 void HeaderMapImpl::removePrefix(const LowerCaseString& prefix) {
-  headers_.remove_if([&](const HeaderEntryImpl& entry) {
+  headers_.remove_if([&prefix, this](const HeaderEntryImpl& entry) {
     bool to_remove = absl::StartsWith(entry.key().getStringView(), prefix.get());
     if (to_remove) {
       // If this header should be removed, make sure any references in the
@@ -546,8 +582,13 @@
       if (cb) {
         StaticLookupResponse ref_lookup_response = cb(*this);
         if (ref_lookup_response.entry_) {
+          const uint32_t key_value_size = (*ref_lookup_response.entry_)->key().size() +
+                                          (*ref_lookup_response.entry_)->value().size();
+          subtractSize(key_value_size);
           *ref_lookup_response.entry_ = nullptr;
         }
+      } else {
+        subtractSize(entry.key().size() + entry.value().size());
       }
     }
     return to_remove;
@@ -570,6 +611,7 @@
 
 HeaderMapImpl::HeaderEntryImpl& HeaderMapImpl::maybeCreateInline(HeaderEntryImpl** entry,
                                                                  const LowerCaseString& key) {
+  cached_byte_size_.reset();
   if (*entry) {
     return **entry;
   }
@@ -588,6 +630,7 @@
     return **entry;
   }
 
+  addSize(key.get().size() + value.size());
   std::list<HeaderEntryImpl>::iterator i = headers_.insert(key, std::move(value));
   i->entry_ = i;
   *entry = &(*i);
@@ -609,6 +652,8 @@
   }
 
   HeaderEntryImpl* entry = *ptr_to_entry;
+  const uint64_t size_to_subtract = entry->entry_->key().size() + entry->entry_->value().size();
+  subtractSize(size_to_subtract);
   *ptr_to_entry = nullptr;
   headers_.erase(entry->entry_);
 }
```
