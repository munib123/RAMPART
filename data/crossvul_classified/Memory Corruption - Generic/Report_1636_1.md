# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1636_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1636_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 41-89 of the vulnerable file.

  }

  return n + p.write('\"');
}

static char unescapeChar(char c) {
  // Optimized for code size on a 8-bit AVR

  const char *p = specialChars + 4;

  for (;;) {
    if (p[0] == '\0') return c;
    if (p[0] == c) return p[1];
    p += 2;
  }
}

static inline bool isQuote(char c) { return c == '\"' || c == '\''; }

char *QuotedString::extractFrom(char *input, char **endPtr) {
  char firstChar = *input;

  if (!isQuote(firstChar)) {
    // must start with a quote
    return NULL;
  }

  char stopChar = firstChar;  // closing quote is the same as opening quote

  char *startPtr = input + 1;  // skip the quote
  char *readPtr = startPtr;
  char *writePtr = startPtr;
  char c;

  for (;;) {
    c = *readPtr++;

    if (c == '\0') {
      // premature ending
      return NULL;
    }

    if (c == stopChar) {
      // closing quote
      break;
    }

    if (c == '\\') {
      // replace char
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,46 +58,44 @@
 static inline bool isQuote(char c) { return c == '\"' || c == '\''; }
 
 char *QuotedString::extractFrom(char *input, char **endPtr) {
-  char firstChar = *input;
-
-  if (!isQuote(firstChar)) {
-    // must start with a quote
-    return NULL;
-  }
-
-  char stopChar = firstChar;  // closing quote is the same as opening quote
-
   char *startPtr = input + 1;  // skip the quote
   char *readPtr = startPtr;
   char *writePtr = startPtr;
   char c;
 
+  char firstChar = *input;
+  char stopChar = firstChar;  // closing quote is the same as opening quote
+
+  if (!isQuote(firstChar)) goto ERROR_OPENING_QUOTE_MISSING;
+
   for (;;) {
     c = *readPtr++;
 
-    if (c == '\0') {
-      // premature ending
-      return NULL;
-    }
+    if (c == '\0') goto ERROR_CLOSING_QUOTE_MISSING;
 
-    if (c == stopChar) {
-      // closing quote
-      break;
-    }
+    if (c == stopChar) goto SUCCESS;
 
     if (c == '\\') {
       // replace char
       c = unescapeChar(*readPtr++);
+      if (c == '\0') goto ERROR_ESCAPE_SEQUENCE_INTERRUPTED;
     }
 
     *writePtr++ = c;
   }
 
+SUCCESS:
   // end the string here
   *writePtr = '\0';
 
   // update end ptr
   *endPtr = readPtr;
 
+  // return pointer to unquoted string
   return startPtr;
+
+ERROR_OPENING_QUOTE_MISSING:
+ERROR_CLOSING_QUOTE_MISSING:
+ERROR_ESCAPE_SEQUENCE_INTERRUPTED:
+  return NULL;
 }
```
