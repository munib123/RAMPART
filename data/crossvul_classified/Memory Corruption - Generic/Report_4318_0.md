# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4318_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4318_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 6240-6280 of the vulnerable file.

  }

  to->len = i;
  to->reach_end = (p == end ? add->reach_end : 0);

  concat_opt_anc_info(&tanc, &to->anc, &add->anc, 1, 1);
  if (! to->reach_end) tanc.right = 0;
  copy_opt_anc_info(&to->anc, &tanc);

  return r;
}

static void
concat_opt_exact_str(OptStr* to, UChar* s, UChar* end, OnigEncoding enc)
{
  int i, j, len;
  UChar *p;

  for (i = to->len, p = s; p < end && i < OPT_EXACT_MAXLEN; ) {
    len = enclen(enc, p);
    if (i + len > OPT_EXACT_MAXLEN) break;
    for (j = 0; j < len && p < end; j++)
      to->s[i++] = *p++;
  }

  to->len = i;

  if (p >= end)
    to->reach_end = 1;
}

static void
alt_merge_opt_exact(OptStr* to, OptStr* add, OptEnv* env)
{
  int i, j, len;

  if (add->len == 0 || to->len == 0) {
    clear_opt_exact(to);
    return ;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6257,7 +6257,7 @@
 
   for (i = to->len, p = s; p < end && i < OPT_EXACT_MAXLEN; ) {
     len = enclen(enc, p);
-    if (i + len > OPT_EXACT_MAXLEN) break;
+    if (i + len >= OPT_EXACT_MAXLEN) break;
     for (j = 0; j < len && p < end; j++)
       to->s[i++] = *p++;
   }
```
