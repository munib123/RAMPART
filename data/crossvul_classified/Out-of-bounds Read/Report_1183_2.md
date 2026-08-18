# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1183_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1183_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 47-87 of the vulnerable file.

    if (*p == '\0' || *p == '#') {return true;}

    // get value
    d.value.str = p;
    while (*p != '\0' && (*p != '#' || *(p-1) == '\\')) ++p;
    
    // remove trailing white space and terminate value
    --p;
    while (*p == ' ' || *p == '\t') --p;
    if (*p == '\\' && *(p + 1) != '\0') ++p;
    ++p;
    d.value.size = p - d.value.str;
    *p = '\0';

    return true;
  }

  char * unescape(char * dest, const char * src)
  {
    while (*src) {
      if (*src == '\\') {
	++src;
	switch (*src) {
	case 'n': *dest = '\n'; break;
	case 'r': *dest = '\r'; break;
	case 't': *dest = '\t'; break;
	case 'f': *dest = '\f'; break;
	case 'v': *dest = '\v'; break;
	default: *dest = *src;
	}
      } else {
	*dest = *src;
      }
      ++src;
      ++dest;
    }
    *dest = '\0';
    return dest;
  }

  bool escape(char * dest, const char * src, size_t limit, const char * others)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,7 @@
   char * unescape(char * dest, const char * src)
   {
     while (*src) {
-      if (*src == '\\') {
+      if (*src == '\\' && src[1]) {
 	++src;
 	switch (*src) {
 	case 'n': *dest = '\n'; break;
```
