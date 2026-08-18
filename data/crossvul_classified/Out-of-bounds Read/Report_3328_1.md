# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3328_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3328_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 77-117 of the vulnerable file.

#define RE_OPCODE_NON_WORD_BOUNDARY     0xB3
#define RE_OPCODE_REPEAT_ANY_GREEDY     0xB4
#define RE_OPCODE_REPEAT_ANY_UNGREEDY   0xB5

#define RE_OPCODE_SPLIT_A               0xC0
#define RE_OPCODE_SPLIT_B               0xC1
#define RE_OPCODE_JUMP                  0xC2
#define RE_OPCODE_REPEAT_START_GREEDY   0xC3
#define RE_OPCODE_REPEAT_END_GREEDY     0xC4
#define RE_OPCODE_REPEAT_START_UNGREEDY 0xC5
#define RE_OPCODE_REPEAT_END_UNGREEDY   0xC6


#define RE_FLAGS_FAST_REGEXP            0x02
#define RE_FLAGS_BACKWARDS              0x04
#define RE_FLAGS_EXHAUSTIVE             0x08
#define RE_FLAGS_WIDE                   0x10
#define RE_FLAGS_NO_CASE                0x20
#define RE_FLAGS_SCAN                   0x40
#define RE_FLAGS_DOT_ALL                0x80
#define RE_FLAGS_NOT_AT_START          0x100
#define RE_FLAGS_GREEDY                0x400
#define RE_FLAGS_UNGREEDY              0x800


typedef struct RE RE;
typedef struct RE_AST RE_AST;
typedef struct RE_NODE RE_NODE;
typedef struct RE_ERROR RE_ERROR;

typedef uint8_t RE_SPLIT_ID_TYPE;


#define CHAR_IN_CLASS(chr, cls)  \
    ((cls)[(chr) / 8] & 1 << ((chr) % 8))


#define IS_WORD_CHAR(chr) \
    (isalnum(chr) || (chr) == '_')


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,7 +94,6 @@
 #define RE_FLAGS_NO_CASE                0x20
 #define RE_FLAGS_SCAN                   0x40
 #define RE_FLAGS_DOT_ALL                0x80
-#define RE_FLAGS_NOT_AT_START          0x100
 #define RE_FLAGS_GREEDY                0x400
 #define RE_FLAGS_UNGREEDY              0x800
 
@@ -105,14 +104,6 @@
 typedef struct RE_ERROR RE_ERROR;
 
 typedef uint8_t RE_SPLIT_ID_TYPE;
-
-
-#define CHAR_IN_CLASS(chr, cls)  \
-    ((cls)[(chr) / 8] & 1 << ((chr) % 8))
-
-
-#define IS_WORD_CHAR(chr) \
-    (isalnum(chr) || (chr) == '_')
 
 
 struct RE_NODE
@@ -213,7 +204,8 @@
 int yr_re_exec(
     uint8_t* re_code,
     uint8_t* input,
-    size_t input_size,
+    size_t input_forwards_size,
+    size_t input_backwards_size,
     int flags,
     RE_MATCH_CALLBACK_FUNC callback,
     void* callback_args);
@@ -222,7 +214,8 @@
 int yr_re_fast_exec(
     uint8_t* re_code,
     uint8_t* input,
-    size_t input_size,
+    size_t input_forwards_size,
+    size_t input_backwards_size,
     int flags,
     RE_MATCH_CALLBACK_FUNC callback,
     void* callback_args);
```
