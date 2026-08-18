# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 797_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `797_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 235-276 of the vulnerable file.

        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == '0') break;
    }
    if (i != used) burl_normalize_qs20_to_plus_fix(b, i);
}


static int burl_normalize_2F_to_slash_fix (buffer *b, int qs, int i)
{
    char * const s = b->ptr;
    const int blen = (int)buffer_string_length(b);
    const int used = qs < 0 ? blen : qs;
    int j = i;
    for (; i < used; ++i, ++j) {
        s[j] = s[i];
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == 'F') {
            s[j] = '/';
            i+=2;
        }
    }
    if (qs >= 0) {
        memmove(s+j, s+qs, blen - qs);
        j += blen - qs;
    }
    buffer_string_set_length(b, j);
    return qs;
}


static int burl_normalize_2F_to_slash (buffer *b, int qs, int flags)
{
    /*("%2F" must already have been uppercased during normalization)*/
    const char * const s = b->ptr;
    const int used = qs < 0 ? (int)buffer_string_length(b) : qs;
    for (int i = 0; i < used; ++i) {
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == 'F') {
            return (flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE)
              ? burl_normalize_2F_to_slash_fix(b, qs, i)
              : -2; /*(flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT)*/
        }
    }
    return qs;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,8 +252,10 @@
         }
     }
     if (qs >= 0) {
-        memmove(s+j, s+qs, blen - qs);
-        j += blen - qs;
+        const int qslen = blen - qs;
+        memmove(s+j, s+qs, (size_t)qslen);
+        qs = j;
+        j += qslen;
     }
     buffer_string_set_length(b, j);
     return qs;
```
