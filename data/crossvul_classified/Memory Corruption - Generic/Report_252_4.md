# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 382-423 of the vulnerable file.

      if (*it == '_')
      {
        mutt_buffer_addch(&buf, ' ');
      }
      else if ((*it == '=') && (!(it[1] & ~127) && hexval(it[1]) != -1) &&
               (!(it[2] & ~127) && hexval(it[2]) != -1))
      {
        mutt_buffer_addch(&buf, (hexval(it[1]) << 4) | hexval(it[2]));
        it += 2;
      }
      else
      {
        mutt_buffer_addch(&buf, *it);
      }
    }
    mutt_buffer_addch(&buf, '\0');
    return buf.data;
  }
  else if (enc == ENCBASE64)
  {
    char *out = mutt_mem_malloc(3 * len / 4 + 1);
    int dlen = mutt_b64_decode(out, it);
    if (dlen == -1)
    {
      FREE(&out);
      return NULL;
    }
    out[dlen] = '\0';
    return out;
  }

  assert(0); /* The enc parameter has an invalid value */
  return NULL;
}

/**
 * rfc2047_encode - RFC2047-encode a string
 * @param d        String to convert
 * @param dlen     Length of string
 * @param col      Starting column to convert
 * @param fromcode Original encoding
 * @param charsets List of allowable encodings (colon separated)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -399,8 +399,9 @@
   }
   else if (enc == ENCBASE64)
   {
-    char *out = mutt_mem_malloc(3 * len / 4 + 1);
-    int dlen = mutt_b64_decode(out, it);
+    const int olen = 3 * len / 4 + 1;
+    char *out = mutt_mem_malloc(olen);
+    int dlen = mutt_b64_decode(out, it, olen);
     if (dlen == -1)
     {
       FREE(&out);
```
