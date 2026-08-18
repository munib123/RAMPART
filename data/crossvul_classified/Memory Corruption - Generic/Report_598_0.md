# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 598_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `598_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 1751-1791 of the vulnerable file.

  char *tmpbuf = nullptr, *resbuf;
  char *s, *t;  /* source, target */
  char *dp;
  int integral;
  int tmplen, reslen=0;
  int count=0;
  int is_negative=0;

  if (d < 0) {
    is_negative = 1;
    d = -d;
  }

  if (dec < 0) dec = 0;
  d = php_math_round(d, dec);

  // departure from PHP: we got rid of dependencies on spprintf() here.
  String tmpstr(63, ReserveString);
  tmpbuf = tmpstr.mutableData();
  tmplen = snprintf(tmpbuf, 64, "%.*F", dec, d);
  if (tmpbuf == nullptr || !isdigit((int)tmpbuf[0])) {
    tmpstr.setSize(tmplen);
    return tmpstr;
  }
  if (tmplen >= 64) {
    // Uncommon, asked for more than 64 chars worth of precision
    tmpstr = String(tmplen, ReserveString);
    tmpbuf = tmpstr.mutableData();
    tmplen = snprintf(tmpbuf, tmplen + 1, "%.*F", dec, d);
    if (tmpbuf == nullptr || !isdigit((int)tmpbuf[0])) {
      tmpstr.setSize(tmplen);
      return tmpstr;
    }
  }

  /* find decimal point, if expected */
  if (dec) {
    dp = strpbrk(tmpbuf, ".,");
  } else {
    dp = nullptr;
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1768,6 +1768,7 @@
   String tmpstr(63, ReserveString);
   tmpbuf = tmpstr.mutableData();
   tmplen = snprintf(tmpbuf, 64, "%.*F", dec, d);
+  if (tmplen < 0) return empty_string();
   if (tmpbuf == nullptr || !isdigit((int)tmpbuf[0])) {
     tmpstr.setSize(tmplen);
     return tmpstr;
@@ -1777,6 +1778,7 @@
     tmpstr = String(tmplen, ReserveString);
     tmpbuf = tmpstr.mutableData();
     tmplen = snprintf(tmpbuf, tmplen + 1, "%.*F", dec, d);
+    if (tmplen < 0) return empty_string();
     if (tmpbuf == nullptr || !isdigit((int)tmpbuf[0])) {
       tmpstr.setSize(tmplen);
       return tmpstr;
```
