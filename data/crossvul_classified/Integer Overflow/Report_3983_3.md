# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3983_3
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3983_3`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 85-125 of the vulnerable file.

        case 0xE0:
            if ( a < 0xA0 ) return 0;
            break;
        case 0xF0:
            if ( a < 0x90 ) return 0;
            break;
        case 0xF4:
            if ( a > 0x8F ) return 0;
            break;
        default:
            if ( a < 0x80 ) return 0;
        }
    case 1:
        if ( *source >= 0x80 && *source < 0xC2 ) return 0;
        if ( *source > 0xF4 ) return 0;
    }
    return 1;
}

/* If the name is part of a db ref ($ref, $db, or $id), then return true. */
static int bson_string_is_db_ref( const unsigned char *string, const int length ) {
    int result = 0;

    if( length >= 4 ) {
        if( string[1] == 'r' && string[2] == 'e' && string[3] == 'f' )
            result = 1;
    }
    else if( length >= 3 ) {
        if( string[1] == 'i' && string[2] == 'd' )
            result = 1;
        else if( string[1] == 'd' && string[2] == 'b' )
            result = 1;
    }

    return result;
}

static int bson_validate_string( bson *b, const unsigned char *string,
                                 const int length, const char check_utf8, const char check_dot,
                                 const char check_dollar ) {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
 }
 
 /* If the name is part of a db ref ($ref, $db, or $id), then return true. */
-static int bson_string_is_db_ref( const unsigned char *string, const int length ) {
+static int bson_string_is_db_ref( const unsigned char *string, const size_t length ) {
     int result = 0;
 
     if( length >= 4 ) {
@@ -120,10 +120,10 @@
 }
 
 static int bson_validate_string( bson *b, const unsigned char *string,
-                                 const int length, const char check_utf8, const char check_dot,
+                                 const size_t length, const char check_utf8, const char check_dot,
                                  const char check_dollar ) {
 
-    int position = 0;
+    size_t position = 0;
     int sequence_length = 1;
 
     if( check_dollar && string[0] == '$' ) {
@@ -155,13 +155,13 @@
 
 
 int bson_check_string( bson *b, const char *string,
-                       const int length ) {
+                       const size_t length ) {
 
     return bson_validate_string( b, ( const unsigned char * )string, length, 1, 0, 0 );
 }
 
 int bson_check_field_name( bson *b, const char *string,
-                           const int length ) {
+                           const size_t length ) {
 
     return bson_validate_string( b, ( const unsigned char * )string, length, 1, 1, 1 );
 }
```
