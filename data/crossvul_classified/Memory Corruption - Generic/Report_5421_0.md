# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5421_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5421_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 215-256 of the vulnerable file.

	return;
    Strcat_charp_n(x, y, strlen(y));
}

void
Strcat_m_charp(Str x, ...)
{
    va_list ap;
    char *p;

    va_start(ap, x);
    while ((p = va_arg(ap, char *)) != NULL)
	 Strcat_charp_n(x, p, strlen(p));
}

void
Strgrow(Str x)
{
    char *old = x->ptr;
    int newlen;
    newlen = x->length * 6 / 5;
    if (newlen == x->length)
	newlen += 2;
    x->ptr = GC_MALLOC_ATOMIC(newlen);
    x->area_size = newlen;
    bcopy((void *)old, (void *)x->ptr, x->length);
    GC_free(old);
}

Str
Strsubstr(Str s, int beg, int len)
{
    Str new_s;
    int i;

    STR_LENGTH_CHECK(s);
    new_s = Strnew();
    if (beg >= s->length)
	return new_s;
    for (i = 0; i < len && beg + i < s->length; i++)
	Strcat_char(new_s, s->ptr[beg + i]);
    return new_s;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -232,8 +232,8 @@
 {
     char *old = x->ptr;
     int newlen;
-    newlen = x->length * 6 / 5;
-    if (newlen == x->length)
+    newlen = x->area_size * 6 / 5;
+    if (newlen == x->area_size)
 	newlen += 2;
     x->ptr = GC_MALLOC_ATOMIC(newlen);
     x->area_size = newlen;
```
