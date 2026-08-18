# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 161_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `161_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1173-1213 of the vulnerable file.

  JsVar *valueOf = jspGetNamedField(v, "valueOf", false);
  if (!jsvIsFunction(valueOf)) {
    jsvUnLock(valueOf);
    return jsvLockAgain(v);
  }
  v = jspeFunctionCall(valueOf, 0, v, false, 0, 0);
  jsvUnLock(valueOf);
  return v;
}

/** Save this var as a string to the given buffer, and return how long it was (return val doesn't include terminating 0)
If the buffer length is exceeded, the returned value will == len */
size_t jsvGetString(const JsVar *v, char *str, size_t len) {
  assert(len>0);
  const char *s = jsvGetConstString(v);
  if (s) {
    /* don't use strncpy here because we don't
     * want to pad the entire buffer with zeros */
    len--;
    int l = 0;
    while (*s && l<len) {
      str[l] = s[l];
      l++;
    }
    str[l] = 0;
    return l;
  } else if (jsvIsInt(v)) {
    itostr(v->varData.integer, str, 10);
    return strlen(str);
  } else if (jsvIsFloat(v)) {
    ftoa_bounded(v->varData.floating, str, len);
    return strlen(str);
  } else if (jsvHasCharacterData(v)) {
    assert(!jsvIsStringExt(v));
    size_t l = len;
    JsvStringIterator it;
    jsvStringIteratorNewConst(&it, v, 0);
    while (jsvStringIteratorHasChar(&it)) {
      if (l--<=1) {
        *str = 0;
        jsvStringIteratorFree(&it);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1190,7 +1190,7 @@
      * want to pad the entire buffer with zeros */
     len--;
     int l = 0;
-    while (*s && l<len) {
+    while (s[l] && l<len) {
       str[l] = s[l];
       l++;
     }
```
