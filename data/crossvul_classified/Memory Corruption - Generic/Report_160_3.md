# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 160_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `160_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 587-627 of the vulnerable file.

  } else {
    val = (JsVarIntUnsigned)vals;
  }
  // work out how many digits
  JsVarIntUnsigned tmp = val;
  int digits = 1;
  while (tmp>=base) {
    digits++;
    tmp /= base;
  }
  // for each digit...
  int i;
  for (i=digits-1;i>=0;i--) {
    str[i] = itoch((int)(val % base));
    val /= base;
  }
  str[digits] = 0;
}

void ftoa_bounded_extra(JsVarFloat val,char *str, size_t len, int radix, int fractionalDigits) {
  const JsVarFloat stopAtError = 0.0000001;
  if (isnan(val)) strncpy(str,"NaN",len);
  else if (!isfinite(val)) {
    if (val<0) strncpy(str,"-Infinity",len);
    else strncpy(str,"Infinity",len);
  } else {
    if (val<0) {
      if (--len <= 0) { *str=0; return; } // bounds check
      *(str++) = '-';
      val = -val;
    }

    // what if we're really close to an integer? Just use that...
    if (((JsVarInt)(val+stopAtError)) == (1+(JsVarInt)val))
      val = (JsVarFloat)(1+(JsVarInt)val);

    JsVarFloat d = 1;
    while (d*radix <= val) d*=radix;
    while (d >= 1) {
      int v = (int)(val / d);
      val -= v*d;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -604,11 +604,12 @@
 }
 
 void ftoa_bounded_extra(JsVarFloat val,char *str, size_t len, int radix, int fractionalDigits) {
+  assert(len>9); // in case if strcpy
   const JsVarFloat stopAtError = 0.0000001;
-  if (isnan(val)) strncpy(str,"NaN",len);
+  if (isnan(val)) strcpy(str,"NaN");
   else if (!isfinite(val)) {
-    if (val<0) strncpy(str,"-Infinity",len);
-    else strncpy(str,"Infinity",len);
+    if (val<0) strcpy(str,"-Infinity");
+    else strcpy(str,"Infinity");
   } else {
     if (val<0) {
       if (--len <= 0) { *str=0; return; } // bounds check
```
