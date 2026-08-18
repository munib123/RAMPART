# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 158_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `158_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 696-736 of the vulnerable file.


void jslReset() {
  jslSeekTo(0);
}



/** When printing out a function, with pretokenise a
 * character could end up being a special token. This
 * handles that case. */
void jslFunctionCharAsString(unsigned char ch, char *str, size_t len) {
  if (ch >= LEX_TOKEN_START) {
    jslTokenAsString(ch, str, len);
  } else {
    str[0] = (char)ch;
    str[1] = 0;
  }
}

void jslTokenAsString(int token, char *str, size_t len) {
  // see JS_ERROR_TOKEN_BUF_SIZE
  if (token>32 && token<128) {
    assert(len>=4);
    str[0] = '\'';
    str[1] = (char)token;
    str[2] = '\'';
    str[3] = 0;
    return;
  }

  switch (token) {
  case LEX_EOF : strncpy(str, "EOF", len); return;
  case LEX_ID : strncpy(str, "ID", len); return;
  case LEX_INT : strncpy(str, "INT", len); return;
  case LEX_FLOAT : strncpy(str, "FLOAT", len); return;
  case LEX_STR : strncpy(str, "STRING", len); return;
  case LEX_UNFINISHED_STR : strncpy(str, "UNFINISHED STRING", len); return;
  case LEX_TEMPLATE_LITERAL : strncpy(str, "TEMPLATE LITERAL", len); return;
  case LEX_UNFINISHED_TEMPLATE_LITERAL : strncpy(str, "UNFINISHED TEMPLATE LITERAL", len); return;
  case LEX_REGEX : strncpy(str, "REGEX", len); return;
  case LEX_UNFINISHED_REGEX : strncpy(str, "UNFINISHED REGEX", len); return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -713,6 +713,7 @@
 }
 
 void jslTokenAsString(int token, char *str, size_t len) {
+  assert(len>28); // size of largest string
   // see JS_ERROR_TOKEN_BUF_SIZE
   if (token>32 && token<128) {
     assert(len>=4);
@@ -723,18 +724,19 @@
     return;
   }
 
+
   switch (token) {
-  case LEX_EOF : strncpy(str, "EOF", len); return;
-  case LEX_ID : strncpy(str, "ID", len); return;
-  case LEX_INT : strncpy(str, "INT", len); return;
-  case LEX_FLOAT : strncpy(str, "FLOAT", len); return;
-  case LEX_STR : strncpy(str, "STRING", len); return;
-  case LEX_UNFINISHED_STR : strncpy(str, "UNFINISHED STRING", len); return;
-  case LEX_TEMPLATE_LITERAL : strncpy(str, "TEMPLATE LITERAL", len); return;
-  case LEX_UNFINISHED_TEMPLATE_LITERAL : strncpy(str, "UNFINISHED TEMPLATE LITERAL", len); return;
-  case LEX_REGEX : strncpy(str, "REGEX", len); return;
-  case LEX_UNFINISHED_REGEX : strncpy(str, "UNFINISHED REGEX", len); return;
-  case LEX_UNFINISHED_COMMENT : strncpy(str, "UNFINISHED COMMENT", len); return;
+  case LEX_EOF : strcpy(str, "EOF"); return;
+  case LEX_ID : strcpy(str, "ID"); return;
+  case LEX_INT : strcpy(str, "INT"); return;
+  case LEX_FLOAT : strcpy(str, "FLOAT"); return;
+  case LEX_STR : strcpy(str, "STRING"); return;
+  case LEX_UNFINISHED_STR : strcpy(str, "UNFINISHED STRING"); return;
+  case LEX_TEMPLATE_LITERAL : strcpy(str, "TEMPLATE LITERAL"); return;
+  case LEX_UNFINISHED_TEMPLATE_LITERAL : strcpy(str, "UNFINISHED TEMPLATE LITERAL"); return;
+  case LEX_REGEX : strcpy(str, "REGEX"); return;
+  case LEX_UNFINISHED_REGEX : strcpy(str, "UNFINISHED REGEX"); return;
+  case LEX_UNFINISHED_COMMENT : strcpy(str, "UNFINISHED COMMENT"); return;
   }
   if (token>=_LEX_OPERATOR_START && token<_LEX_R_LIST_END) {
     const char tokenNames[] =
@@ -809,11 +811,10 @@
       n--; // next token
     }
     assert(n==0);
-    strncpy(str, &tokenNames[p], len);
+    strcpy(str, &tokenNames[p]);
     return;
   }
 
-  assert(len>=10);
   espruino_snprintf(str, len, "?[%d]", token);
 }
 
```
