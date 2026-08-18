# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4233_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4233_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 125-166 of the vulnerable file.

    }
    count = r_size(op1) - size;
    ptr = op1->value.bytes;
    if (size == 0)
        goto found;
    if (!forward)
        ptr += count;
    pat = op->value.bytes;
    ch = pat[0];
    do {
        if (*ptr == ch && (size == 1 || !memcmp(ptr, pat, size)))
            goto found;
        ptr += incr;
    }
    while (count--);
    /* No match */
    make_false(op);
    return 0;
found:
    op->tas.type_attrs = op1->tas.type_attrs;
    op->value.bytes = ptr;
    r_set_size(op, size);
    push(2);
    op[-1] = *op1;
    r_set_size(op - 1, ptr - op[-1].value.bytes);
    op1->value.bytes = ptr + size;
    r_set_size(op1, count + (!forward ? (size - 1) : 0));
    make_true(op);
    return 0;
}

/* Search from the start of the string */
static int
zsearch(i_ctx_t *i_ctx_p)
{
    return search_impl(i_ctx_p, true);
}

/* Search from the end of the string */
static int
zrsearch(i_ctx_t *i_ctx_p)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,13 +142,18 @@
     return 0;
 found:
     op->tas.type_attrs = op1->tas.type_attrs;
-    op->value.bytes = ptr;
-    r_set_size(op, size);
+    op->value.bytes = ptr;				/* match */
+    op->tas.rsize = size;				/* match */
     push(2);
-    op[-1] = *op1;
-    r_set_size(op - 1, ptr - op[-1].value.bytes);
-    op1->value.bytes = ptr + size;
-    r_set_size(op1, count + (!forward ? (size - 1) : 0));
+    op[-1] = *op1;					/* pre */
+    op[-3].value.bytes = ptr + size;			/* post */
+    if (forward) {
+        op[-1].tas.rsize = ptr - op[-1].value.bytes;	/* pre */
+        op[-3].tas.rsize = count;			/* post */
+    } else {
+        op[-1].tas.rsize = count;			/* pre */
+        op[-3].tas.rsize -= count + size;		/* post */
+    }
     make_true(op);
     return 0;
 }
```
