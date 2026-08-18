# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2045_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2045_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 94-134 of the vulnerable file.

  unsigned *value,
  unsigned  count)

  {
  int  c;
  unsigned locval;
  unsigned ndigs;
  char  *cp;
  char  scratch[DIS_BUFSIZ+1];

  assert(negate != NULL);
  assert(value != NULL);
  assert(count);
  assert(stream >= 0);
  assert(dis_getc != NULL);
  assert(dis_gets != NULL);

  memset(scratch, 0, DIS_BUFSIZ+1);
  if (dis_umaxd == 0)
    disiui_();

  switch (c = (*dis_getc)(stream))
    {

    case '-':

    case '+':

      *negate = c == '-';

      if ((*dis_gets)(stream, scratch, count) != (int)count)
        {
        return(DIS_EOD);
        }

      if (count >= dis_umaxd)
        {
        if (count > dis_umaxd)
          goto overflow;

        if (memcmp(scratch, dis_umax, dis_umaxd) > 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,6 +112,15 @@
   if (dis_umaxd == 0)
     disiui_();
 
+  if (count >= dis_umaxd)
+    {
+    if (count > dis_umaxd)
+      goto overflow;
+
+    if (memcmp(scratch, dis_umax, dis_umaxd) > 0)
+      goto overflow;
+    }
+
   switch (c = (*dis_getc)(stream))
     {
 
```
