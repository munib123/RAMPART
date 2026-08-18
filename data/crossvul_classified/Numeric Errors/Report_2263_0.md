# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 2263_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2263_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```cpp
Lines 609-650 of the vulnerable file.

    input += len_search;
    pos += len_search;
  }
  n = len;
  if (n > pos) {
    n -= pos;
    memcpy(p, input, n);
    p += n;
  }
  retString.setSize(p - ret);
  return retString;
}

///////////////////////////////////////////////////////////////////////////////

String string_chunk_split(const char *src, int srclen, const char *end,
                          int endlen, int chunklen) {
  int chunks = srclen / chunklen; // complete chunks!
  int restlen = srclen - chunks * chunklen; /* srclen % chunklen */

  int out_len = (chunks + 1) * endlen + srclen;
  String ret(out_len, ReserveString);
  char *dest = ret.bufferSlice().ptr;

  const char *p; char *q;
  const char *pMax = src + srclen - chunklen + 1;
  for (p = src, q = dest; p < pMax; ) {
    memcpy(q, p, chunklen);
    q += chunklen;
    memcpy(q, end, endlen);
    q += endlen;
    p += chunklen;
  }

  if (restlen) {
    memcpy(q, p, restlen);
    q += restlen;
    memcpy(q, end, endlen);
    q += endlen;
  }

  ret.setSize(q - dest);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -626,8 +626,14 @@
   int chunks = srclen / chunklen; // complete chunks!
   int restlen = srclen - chunks * chunklen; /* srclen % chunklen */
 
-  int out_len = (chunks + 1) * endlen + srclen;
-  String ret(out_len, ReserveString);
+  String ret(
+    safe_address(
+      chunks + 1,
+      endlen,
+      srclen
+    ),
+    ReserveString
+  );
   char *dest = ret.bufferSlice().ptr;
 
   const char *p; char *q;
```
