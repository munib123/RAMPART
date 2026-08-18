# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 160_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `160_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 797-839 of the vulnerable file.

        /*LEX_R_VOID :     */ "void\0"
        /*LEX_R_DEBUGGER : */ "debugger\0"
        /*LEX_R_CLASS :    */ "class\0"
        /*LEX_R_EXTENDS :  */ "extends\0"
        /*LEX_R_SUPER :  */   "super\0"
        /*LEX_R_STATIC :   */ "static\0"
        ;
    unsigned int p = 0;
    int n = token-_LEX_OPERATOR_START;
    while (n>0 && p<sizeof(tokenNames)) {
      while (tokenNames[p] && p<sizeof(tokenNames)) p++;
      p++; // skip the zero
      n--; // next token
    }
    assert(n==0);
    strncpy(str, &tokenNames[p], len);
    return;
  }

  assert(len>=10);
  strncpy(str, "?[",len);
  itostr(token, &str[2], 10);
  strncat(str, "]",len);
}

void jslGetTokenString(char *str, size_t len) {
  if (lex->tk == LEX_ID) {
    strncpy(str, "ID:", len);
    strncat(str, jslGetTokenValueAsString(), len);
  } else if (lex->tk == LEX_STR) {
    strncpy(str, "String:'", len);
    strncat(str, jslGetTokenValueAsString(), len);
    strncat(str, "'", len);
  } else
    jslTokenAsString(lex->tk, str, len);
}

char *jslGetTokenValueAsString() {
  assert(lex->tokenl < JSLEX_MAX_TOKEN_LENGTH);
  lex->token[lex->tokenl]  = 0; // add final null
  return lex->token;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -814,19 +814,14 @@
   }
 
   assert(len>=10);
-  strncpy(str, "?[",len);
-  itostr(token, &str[2], 10);
-  strncat(str, "]",len);
+  espruino_snprintf(str, len, "?[%d]", token);
 }
 
 void jslGetTokenString(char *str, size_t len) {
   if (lex->tk == LEX_ID) {
-    strncpy(str, "ID:", len);
-    strncat(str, jslGetTokenValueAsString(), len);
+    espruino_snprintf(str, len, "ID:%s", jslGetTokenValueAsString());
   } else if (lex->tk == LEX_STR) {
-    strncpy(str, "String:'", len);
-    strncat(str, jslGetTokenValueAsString(), len);
-    strncat(str, "'", len);
+    espruino_snprintf(str, len, "String:'%s'", jslGetTokenValueAsString());
   } else
     jslTokenAsString(lex->tk, str, len);
 }
```
