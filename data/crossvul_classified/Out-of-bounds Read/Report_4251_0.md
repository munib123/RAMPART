# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4251_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4251_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 436-476 of the vulnerable file.

    if (*p++ != 'l') return false;
    top++->m_type = KindOfNull;
    return true;
  }

  bool handleBackslash(signed char& out) {
    char ch = *p++;
    switch (ch) {
      case 0: return false;
      case '"': out = ch; return true;
      case '\\': out = ch; return true;
      case '/': out = ch; return true;
      case 'b': out = '\b'; return true;
      case 'f': out = '\f'; return true;
      case 'n': out = '\n'; return true;
      case 'r': out = '\r'; return true;
      case 't': out = '\t'; return true;
      case 'u': {
        if (UNLIKELY(is_tsimplejson)) {
          auto const ch1 = *p++;
          auto const ch2 = *p++;
          auto const dch3 = dehexchar(*p++);
          auto const dch4 = dehexchar(*p++);
          if (UNLIKELY(ch1 != '0' || ch2 != '0' || dch3 < 0 || dch4 < 0)) {
            return false;
          }
          out = (dch3 << 4) | dch4;
          return true;
        } else {
          uint16_t u16cp = 0;
          for (int i = 0; i < 4; i++) {
            auto const hexv = dehexchar(*p++);
            if (hexv < 0) return false; // includes check for end of string
            u16cp <<= 4;
            u16cp |= hexv;
          }
          if (u16cp > 0x7f) {
            return false;
          } else {
            out = u16cp;
            return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -453,12 +453,13 @@
       case 'u': {
         if (UNLIKELY(is_tsimplejson)) {
           auto const ch1 = *p++;
+          if (UNLIKELY(ch1 != '0')) return false;
           auto const ch2 = *p++;
+          if (UNLIKELY(ch2 != '0')) return false;
           auto const dch3 = dehexchar(*p++);
+          if (UNLIKELY(dch3 < 0)) return false;
           auto const dch4 = dehexchar(*p++);
-          if (UNLIKELY(ch1 != '0' || ch2 != '0' || dch3 < 0 || dch4 < 0)) {
-            return false;
-          }
+          if (UNLIKELY(dch4 < 0)) return false;
           out = (dch3 << 4) | dch4;
           return true;
         } else {
```
