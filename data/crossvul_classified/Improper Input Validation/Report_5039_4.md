# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5039_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5039_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.

/* Read one byte from stream, convert to unsigned char, then int, and
   return. return EOF on end of file. This corresponds to the
   behaviour of fgetc(). */
typedef int (*get_func)(void *data);

typedef struct {
    get_func get;
    void *data;
    char buffer[5];
    size_t buffer_pos;
    int state;
    int line;
    int column, last_column;
    size_t position;
} stream_t;

typedef struct {
    stream_t stream;
    strbuffer_t saved_text;
    size_t flags;
    int token;
    union {
        struct {
            char *val;
            size_t len;
        } string;
        json_int_t integer;
        double real;
    } value;
} lex_t;

#define stream_to_lex(stream) container_of(stream, lex_t, stream)


/*** error reporting ***/

static void error_set(json_error_t *error, const lex_t *lex,
                      const char *msg, ...)
{
    va_list ap;
    char msg_text[JSON_ERROR_TEXT_LENGTH];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,7 @@
     stream_t stream;
     strbuffer_t saved_text;
     size_t flags;
+    size_t depth;
     int token;
     union {
         struct {
@@ -803,6 +804,12 @@
 {
     json_t *json;
 
+    lex->depth++;
+    if(lex->depth > JSON_PARSER_MAX_DEPTH) {
+        error_set(error, lex, "maximum parsing depth reached");
+        return NULL;
+    }
+
     switch(lex->token) {
         case TOKEN_STRING: {
             const char *value = lex->value.string.val;
@@ -865,12 +872,15 @@
     if(!json)
         return NULL;
 
+    lex->depth--;
     return json;
 }
 
 static json_t *parse_json(lex_t *lex, size_t flags, json_error_t *error)
 {
     json_t *result;
+
+    lex->depth = 0;
 
     lex_scan(lex, error);
     if(!(flags & JSON_DECODE_ANY)) {
```
