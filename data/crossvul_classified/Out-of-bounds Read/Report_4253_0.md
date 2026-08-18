# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4253_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4253_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 325-366 of the vulnerable file.

 * - Arrays nested > 255 levels
 */
struct SimpleParser {
  static constexpr int kMaxArrayDepth = 255;

  /*
   * Returns buffer size in bytes needed to handle any input up to given length.
   */
  static size_t BufferBytesForLength(int length) {
    return (length + 1) * sizeof(TypedValue) / 2;  // Worst case: "[0,0,...,0]"
  }

  /*
   * Returns false for unsupported or malformed input (does not distinguish).
   */
  static bool TryParse(const char* inp, int length,
                       TypedValue* buf, Variant& out,
                       JSONContainerType container_type, bool is_tsimplejson) {
    SimpleParser parser(inp, length, buf, container_type, is_tsimplejson);
    bool ok = parser.parseValue();
    parser.skipSpace();
    if (!ok || parser.p != inp + length) {
      // Unsupported, malformed, or trailing garbage. Release entire stack.
      tvDecRefRange(buf, parser.top);
      return false;
    }
    out = Variant::attach(*--parser.top);
    return true;
  }

 private:
  SimpleParser(const char* input, int length, TypedValue* buffer,
               JSONContainerType container_type, bool is_tsimplejson)
    : p(input)
    , top(buffer)
    , array_depth(-kMaxArrayDepth) /* Start negative to simplify check. */
    , container_type(container_type)
    , is_tsimplejson(is_tsimplejson)
  {
    assertx(input[length] == 0);  // Parser relies on sentinel to avoid checks.
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -342,8 +342,8 @@
                        JSONContainerType container_type, bool is_tsimplejson) {
     SimpleParser parser(inp, length, buf, container_type, is_tsimplejson);
     bool ok = parser.parseValue();
-    parser.skipSpace();
-    if (!ok || parser.p != inp + length) {
+    if (!ok ||
+        (parser.skipSpace(), parser.p != inp + length)) {
       // Unsupported, malformed, or trailing garbage. Release entire stack.
       tvDecRefRange(buf, parser.top);
       return false;
```
