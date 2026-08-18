# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4252_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4252_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1131-1171 of the vulnerable file.

 * DARRAYS              | true     | "{}"       => darray
 * DARRAYS              | false    | "{}"       => stdClass
 * DARRAYS              | true     | "[]"       => darray
 * DARRAYS              | false    | "[]"       => stdClass
 *
 * DARRAYS_AND_VARRAYS  | true     | "{}"       => darray
 * DARRAYS_AND_VARRAYS  | false    | "{}"       => stdClass
 * DARRAYS_AND_VARRAYS  | true     | "[]"       => varray
 * DARRAYS_AND_VARRAYS  | false    | "[]"       => stdClass
 */
bool JSON_parser(Variant &z, const char *p, int length, bool const assoc,
                 int depth, int64_t options) {
  // No GC safepoints during JSON parsing, please. Code is not re-entrant.
  NoHandleSurpriseScope no_surprise(SafepointFlags);

  json_parser *json = s_json_parser.get(); /* the parser state */
  // Clear and reuse the thread-local string buffers. They are only freed if
  // they exceed kMaxPersistentStringBufferCapacity at exit or if the thread
  // is explicitly flushed (e.g., due to being idle).
  json->initSb(length);
  SCOPE_EXIT {
    constexpr int kMaxPersistentStringBufferCapacity = 256 * 1024;
    if (json->sb_cap > kMaxPersistentStringBufferCapacity) json->flushSb();
  };
  // SimpleParser only handles the most common set of options. Also, only use it
  // if its array nesting depth check is *more* restrictive than what the user
  // asks for, to ensure that the precise semantics of the general case is
  // applied for all nesting overflows.
  if (assoc &&
      options == (options & (k_JSON_FB_LOOSE |
                             k_JSON_FB_DARRAYS |
                             k_JSON_FB_DARRAYS_AND_VARRAYS |
                             k_JSON_FB_HACK_ARRAYS |
                             k_JSON_FB_THRIFT_SIMPLE_JSON |
                             k_JSON_FB_LEGACY_HACK_ARRAYS)) &&
      depth >= SimpleParser::kMaxArrayDepth &&
      length <= RuntimeOption::EvalSimpleJsonMaxLength &&
      SimpleParser::TryParse(p, length, json->tl_buffer.tv, z,
                             get_container_type_from_options(options),
                             options & k_JSON_FB_THRIFT_SIMPLE_JSON)) {
    return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1148,6 +1148,10 @@
   // they exceed kMaxPersistentStringBufferCapacity at exit or if the thread
   // is explicitly flushed (e.g., due to being idle).
   json->initSb(length);
+  if (depth <= 0) {
+    json->error_code = json_error_codes::JSON_ERROR_DEPTH;
+    return false;
+  }
   SCOPE_EXIT {
     constexpr int kMaxPersistentStringBufferCapacity = 256 * 1024;
     if (json->sb_cap > kMaxPersistentStringBufferCapacity) json->flushSb();
```
