# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3983_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3983_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 89-129 of the vulnerable file.

    bson_init_data( b, data );
    b->finished = 1;
    return BSON_OK;
}

static void _bson_reset( bson *b ) {
    b->finished = 0;
    b->stackPos = 0;
    b->err = 0;
    b->errstr = NULL;
}

MONGO_EXPORT int bson_size( const bson *b ) {
    int i;
    if ( ! b || ! b->data )
        return 0;
    bson_little_endian32( &i, b->data );
    return i;
}

MONGO_EXPORT int bson_buffer_size( const bson *b ) {
    return (b->cur - b->data + 1);
}


MONGO_EXPORT const char *bson_data( const bson *b ) {
    return (const char *)b->data;
}

static char hexbyte( char hex ) {
    if (hex >= '0' && hex <= '9')
        return (hex - '0');
    else if (hex >= 'A' && hex <= 'F')
        return (hex - 'A' + 10);
    else if (hex >= 'a' && hex <= 'f')
        return (hex - 'a' + 10);
    else
        return 0x0;
}

MONGO_EXPORT void bson_oid_from_string( bson_oid_t *oid, const char *str ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,7 +106,7 @@
     return i;
 }
 
-MONGO_EXPORT int bson_buffer_size( const bson *b ) {
+MONGO_EXPORT size_t bson_buffer_size( const bson *b ) {
     return (b->cur - b->data + 1);
 }
 
@@ -306,7 +306,7 @@
 }
 
 MONGO_EXPORT bson_type bson_iterator_next( bson_iterator *i ) {
-    int ds;
+    size_t ds;
 
     if ( i->first ) {
         i->first = 0;
@@ -420,7 +420,7 @@
     case BSON_INT:
         return bson_iterator_int_raw( i );
     case BSON_LONG:
-        return bson_iterator_long_raw( i );
+        return ( int )bson_iterator_long_raw( i );
     case BSON_DOUBLE:
         return bson_iterator_double_raw( i );
     default:
@@ -604,7 +604,7 @@
     b->cur++;
 }
 
-static void bson_append( bson *b, const void *data, int len ) {
+static void bson_append( bson *b, const void *data, size_t len ) {
     memcpy( b->cur , data , len );
     b->cur += len;
 }
@@ -614,12 +614,17 @@
     b->cur += 4;
 }
 
+static void bson_append32_as_int( bson *b, int data ) {
+    bson_little_endian32( b->cur, &data );
+    b->cur += 4;
+}
+
 static void bson_append64( bson *b, const void *data ) {
     bson_little_endian64( b->cur, data );
     b->cur += 8;
 }
 
-int bson_ensure_space( bson *b, const int bytesNeeded ) {
+int bson_ensure_space( bson *b, const size_t bytesNeeded ) {
     int pos = b->cur - b->data;
     char *orig = b->data;
     int new_size;
@@ -657,7 +662,7 @@
     if ( ! b->finished ) {
         if ( bson_ensure_space( b, 1 ) == BSON_ERROR ) return BSON_ERROR;
         bson_append_byte( b, 0 );
-        i = b->cur - b->data;
+        i = ( int )( b->cur - b->data );
         bson_little_endian32( b->data, &i );
         b->finished = 1;
     }
@@ -675,7 +680,7 @@
     }
 }
 
-static int bson_append_estart( bson *b, int type, const char *name, const int dataSize ) {
+static int bson_append_estart( bson *b, int type, const char *name, const size_t dataSize ) {
     const int len = strlen( name ) + 1;
 
     if ( b->finished ) {
@@ -742,15 +747,15 @@
 }
 
 static int bson_append_string_base( bson *b, const char *name,
-                                    const char *value, int len, bson_type type ) {
-
-    int sl = len + 1;
+                                    const char *value, size_t len, bson_type type ) {
+
+    size_t sl = len + 1;
     if ( bson_check_string( b, ( const char * )value, sl - 1 ) == BSON_ERROR )
         return BSON_ERROR;
     if ( bson_append_estart( b, type, name, 4 + sl ) == BSON_ERROR ) {
         return BSON_ERROR;
     }
-    bson_append32( b , &sl );
+    bson_append32_as_int( b , ( int )sl );
     bson_append( b , value , sl - 1 );
     bson_append( b , "\0" , 1 );
     return BSON_OK;
@@ -768,28 +773,28 @@
     return bson_append_string_base( b, name, value, strlen ( value ), BSON_CODE );
 }
 
-MONGO_EXPORT int bson_append_string_n( bson *b, const char *name, const char *value, int len ) {
+MONGO_EXPORT int bson_append_string_n( bson *b, const char *name, const char *value, size_t len ) {
     return bson_append_string_base( b, name, value, len, BSON_STRING );
 }
 
-MONGO_EXPORT int bson_append_symbol_n( bson *b, const char *name, const char *value, int len ) {
+MONGO_EXPORT int bson_append_symbol_n( bson *b, const char *name, const char *value, size_t len ) {
     return bson_append_string_base( b, name, value, len, BSON_SYMBOL );
 }
 
-MONGO_EXPORT int bson_append_code_n( bson *b, const char *name, const char *value, int len ) {
+MONGO_EXPORT int bson_append_code_n( bson *b, const char *name, const char *value, size_t len ) {
     return bson_append_string_base( b, name, value, len, BSON_CODE );
 }
 
 MONGO_EXPORT int bson_append_code_w_scope_n( bson *b, const char *name,
-        const char *code, int len, const bson *scope ) {
-
-    int sl, size;
+        const char *code, size_t len, const bson *scope ) {
+
+    size_t sl, size;
     if ( !scope ) return BSON_ERROR;
     sl = len + 1;
     size = 4 + 4 + sl + bson_size( scope );
     if ( bson_append_estart( b, BSON_CODEWSCOPE, name, size ) == BSON_ERROR )
         return BSON_ERROR;
-    bson_append32( b, &size );
+    bson_append32_as_int( b, ( int )size );
     bson_append32( b, &sl );
     bson_append( b, code, sl );
     bson_append( b, scope->data, bson_size( scope ) );
@@ -800,20 +805,20 @@
     return bson_append_code_w_scope_n( b, name, code, strlen ( code ), scope );
 }
 
-MONGO_EXPORT int bson_append_binary( bson *b, const char *name, char type, const char *str, int len ) {
+MONGO_EXPORT int bson_append_binary( bson *b, const char *name, char type, const char *str, size_t len ) {
     if ( type == BSON_BIN_BINARY_OLD ) {
         int subtwolen = len + 4;
         if ( bson_append_estart( b, BSON_BINDATA, name, 4+1+4+len ) == BSON_ERROR )
             return BSON_ERROR;
-        bson_append32( b, &subtwolen );
+        bson_append32_as_int( b, ( int )subtwolen );
         bson_append_byte( b, type );
-        bson_append32( b, &len );
+        bson_append32_as_int( b, ( int )len );
         bson_append( b, str, len );
     }
     else {
         if ( bson_append_estart( b, BSON_BINDATA, name, 4+1+len ) == BSON_ERROR )
             return BSON_ERROR;
-        bson_append32( b, &len );
+        bson_append32_as_int( b, ( int )len );
         bson_append_byte( b, type );
         bson_append( b, str, len );
     }
@@ -834,8 +839,8 @@
 }
 
 MONGO_EXPORT int bson_append_regex( bson *b, const char *name, const char *pattern, const char *opts ) {
-    const int plen = strlen( pattern )+1;
-    const int olen = strlen( opts )+1;
+    const size_t plen = strlen( pattern )+1;
+    const size_t olen = strlen( opts )+1;
     if ( bson_append_estart( b, BSON_REGEX, name, plen + olen ) == BSON_ERROR )
         return BSON_ERROR;
     if ( bson_check_string( b, pattern, plen - 1 ) == BSON_ERROR )
@@ -855,7 +860,7 @@
 
 MONGO_EXPORT int bson_append_element( bson *b, const char *name_or_null, const bson_iterator *elem ) {
     bson_iterator next = *elem;
-    int size;
+    size_t size;
 
     bson_iterator_next( &next );
     size = next.cur - elem->cur;
@@ -866,7 +871,7 @@
         bson_append( b, elem->cur, size );
     }
     else {
-        int data_size = size - 2 - strlen( bson_iterator_key( elem ) );
+        size_t data_size = size - 2 - strlen( bson_iterator_key( elem ) );
         bson_append_estart( b, elem->cur[0], name_or_null, data_size );
         bson_append( b, bson_iterator_value( elem ), data_size );
     }
@@ -922,7 +927,7 @@
     bson_append_byte( b , 0 );
 
     start = b->data + b->stack[ --b->stackPos ];
-    i = b->cur - start;
+    i = ( int )( b->cur - start );
     bson_little_endian32( start, &i );
 
     return BSON_OK;
@@ -950,14 +955,14 @@
     bson_free_func( ptr );
 }
 
-MONGO_EXPORT void *bson_malloc( int size ) {
+MONGO_EXPORT void *bson_malloc( size_t size ) {
     void *p;
     p = bson_malloc_func( size );
     bson_fatal_msg( !!p, "malloc() failed" );
     return p;
 }
 
-void *bson_realloc( void *ptr, int size ) {
+void *bson_realloc( void *ptr, size_t size ) {
     void *p;
     p = bson_realloc_func( ptr, size );
     bson_fatal_msg( !!p, "realloc() failed" );
```
