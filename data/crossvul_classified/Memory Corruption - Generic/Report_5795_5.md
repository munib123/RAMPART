# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5795_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5795_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 64-104 of the vulnerable file.

static const char json_true_str[] = "true";
static const int json_true_str_len = sizeof(json_true_str) - 1;
static const char json_false_str[] = "false";
static const int json_false_str_len = sizeof(json_false_str) - 1;

static const char* json_tokener_errors[] = {
  "success",
  "continue",
  "nesting too deep",
  "unexpected end of data",
  "unexpected character",
  "null expected",
  "boolean expected",
  "number expected",
  "array value separator ',' expected",
  "quoted object property name expected",
  "object property name separator ':' expected",
  "object value separator ',' expected",
  "invalid string sequence",
  "expected comment",
};

const char *json_tokener_error_desc(enum json_tokener_error jerr)
{
	int jerr_int = (int)jerr;
	if (jerr_int < 0 || jerr_int >= (int)(sizeof(json_tokener_errors) / sizeof(json_tokener_errors[0])))
		return "Unknown error, invalid json_tokener_error value passed to json_tokener_error_desc()";
	return json_tokener_errors[jerr];
}

enum json_tokener_error json_tokener_get_error(json_tokener *tok)
{
	return tok->err;
}

/* Stuff for decoding unicode sequences */
#define IS_HIGH_SURROGATE(uc) (((uc) & 0xFC00) == 0xD800)
#define IS_LOW_SURROGATE(uc)  (((uc) & 0xFC00) == 0xDC00)
#define DECODE_SURROGATE_PAIR(hi,lo) ((((hi) & 0x3FF) << 10) + ((lo) & 0x3FF) + 0x10000)
static unsigned char utf8_replacement_char[3] = { 0xEF, 0xBF, 0xBD };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,6 +81,7 @@
   "object value separator ',' expected",
   "invalid string sequence",
   "expected comment",
+  "buffer size overflow"
 };
 
 const char *json_tokener_error_desc(enum json_tokener_error jerr)
@@ -242,6 +243,16 @@
 
   tok->char_offset = 0;
   tok->err = json_tokener_success;
+
+  /* this interface is presently not 64-bit clean due to the int len argument
+     and the internal printbuf interface that takes 32-bit int len arguments
+     so the function limits the maximum string size to INT32_MAX (2GB).
+     If the function is called with len == -1 then strlen is called to check
+     the string length is less than INT32_MAX (2GB) */
+  if ((len < -1) || (len == -1 && strlen(str) > INT32_MAX)) {
+    tok->err = json_tokener_error_size;
+    return NULL;
+  }
 
   while (PEEK_CHAR(c, tok)) {
 
```
