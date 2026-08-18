# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3983_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3983_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 118-158 of the vulnerable file.

    BSON_CODE = 13,
    BSON_SYMBOL = 14,
    BSON_CODEWSCOPE = 15,
    BSON_INT = 16,
    BSON_TIMESTAMP = 17,
    BSON_LONG = 18
} bson_type;

typedef int bson_bool_t;

typedef struct {
    const char *cur;
    bson_bool_t first;
} bson_iterator;

typedef struct {
    char *data;    /**< Pointer to a block of data in this BSON object. */
    char *cur;     /**< Pointer to the current position. */
    int dataSize;  /**< The number of bytes allocated to char *data. */
    bson_bool_t finished; /**< When finished, the BSON object can no longer be modified. */
    int stack[32];        /**< A stack used to keep track of nested BSON elements. */
    int stackPos;         /**< Index of current stack position. */
    int err; /**< Bitfield representing errors or warnings on this buffer */
    char *errstr; /**< A string representation of the most recent error or warning. */
} bson;

#pragma pack(1)
typedef union {
    char bytes[12];
    int ints[3];
} bson_oid_t;
#pragma pack()

typedef int64_t bson_date_t; /* milliseconds since epoch UTC */

typedef struct {
    int i; /* increment */
    int t; /* time in seconds */
} bson_timestamp_t;

/* ----------------------------
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,7 +135,7 @@
     char *cur;     /**< Pointer to the current position. */
     int dataSize;  /**< The number of bytes allocated to char *data. */
     bson_bool_t finished; /**< When finished, the BSON object can no longer be modified. */
-    int stack[32];        /**< A stack used to keep track of nested BSON elements. */
+    size_t stack[32];        /**< A stack used to keep track of nested BSON elements. */
     int stackPos;         /**< Index of current stack position. */
     int err; /**< Bitfield representing errors or warnings on this buffer */
     char *errstr; /**< A string representation of the most recent error or warning. */
@@ -170,7 +170,7 @@
  * @return the size.
  */
 MONGO_EXPORT int bson_size( const bson *b );
-MONGO_EXPORT int bson_buffer_size( const bson *b );
+MONGO_EXPORT size_t bson_buffer_size( const bson *b );
 
 /**
  * Print a string representation of a BSON object.
@@ -602,7 +602,7 @@
  * @return BSON_OK or BSON_ERROR with the bson error object set.
  *   Exits if allocation fails.
  */
-int bson_ensure_space( bson *b, const int bytesNeeded );
+int bson_ensure_space( bson *b, const size_t bytesNeeded );
 
 /**
  * Finalize a bson object.
@@ -717,7 +717,7 @@
  *
  * @return BSON_OK or BSON_ERROR.
  */
-MONGO_EXPORT int bson_append_string_n( bson *b, const char *name, const char *str, int len );
+MONGO_EXPORT int bson_append_string_n( bson *b, const char *name, const char *str, size_t len );
 
 /**
  * Append a symbol to a bson.
@@ -740,7 +740,7 @@
  *
  * @return BSON_OK or BSON_ERROR.
  */
-MONGO_EXPORT int bson_append_symbol_n( bson *b, const char *name, const char *str, int len );
+MONGO_EXPORT int bson_append_symbol_n( bson *b, const char *name, const char *str, size_t len );
 
 /**
  * Append code to a bson.
@@ -764,7 +764,7 @@
  *
  * @return BSON_OK or BSON_ERROR.
  */
-MONGO_EXPORT int bson_append_code_n( bson *b, const char *name, const char *str, int len );
+MONGO_EXPORT int bson_append_code_n( bson *b, const char *name, const char *str, size_t len );
 
 /**
  * Append code to a bson with scope.
@@ -789,7 +789,7 @@
  *
  * @return BSON_OK or BSON_ERROR.
  */
-MONGO_EXPORT int bson_append_code_w_scope_n( bson *b, const char *name, const char *code, int size, const bson *scope );
+MONGO_EXPORT int bson_append_code_w_scope_n( bson *b, const char *name, const char *code, size_t size, const bson *scope );
 
 /**
  * Append binary data to a bson.
@@ -802,7 +802,7 @@
  *
  * @return BSON_OK or BSON_ERROR.
  */
-MONGO_EXPORT int bson_append_binary( bson *b, const char *name, char type, const char *str, int len );
+MONGO_EXPORT int bson_append_binary( bson *b, const char *name, char type, const char *str, size_t len );
 
 /**
  * Append a bson_bool_t to a bson.
@@ -977,7 +977,7 @@
  *
  * @sa malloc(3)
  */
-MONGO_EXPORT void *bson_malloc( int size );
+MONGO_EXPORT void *bson_malloc( size_t size );
 
 /**
  * Changes the size of allocated memory and checks return value,
@@ -990,7 +990,7 @@
  *
  * @sa realloc()
  */
-void *bson_realloc( void *ptr, int size );
+void *bson_realloc( void *ptr, size_t size );
 
 /**
  * Set a function for error handling.
```
