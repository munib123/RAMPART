# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3983_4
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3983_4`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 18-54 of the vulnerable file.

#define BSON_ENCODING_H_

MONGO_EXTERN_C_START

/**
 * Check that a field name is valid UTF8, does not start with a '$',
 * and contains no '.' characters. Set bson bit field appropriately.
 * Note that we don't need to check for '\0' because we're using
 * strlen(3), which stops at '\0'.
 *
 * @param b The bson object to which field name will be appended.
 * @param string The field name as char*.
 * @param length The length of the field name.
 *
 * @return BSON_OK if valid UTF8 and BSON_ERROR if not. All BSON strings must be
 *     valid UTF8. This function will also check whether the string
 *     contains '.' or starts with '$', since the validity of this depends on context.
 *     Set the value of b->err appropriately.
 */
int bson_check_field_name( bson *b, const char *string,
                           const int length );

/**
 * Check that a string is valid UTF8. Sets the buffer bit field appropriately.
 *
 * @param b The bson object to which string will be appended.
 * @param string The string to check.
 * @param length The length of the string.
 *
 * @return BSON_OK if valid UTF-8; otherwise, BSON_ERROR.
 *     Sets b->err on error.
 */
bson_bool_t bson_check_string( bson *b, const char *string,
                               const int length );

MONGO_EXTERN_C_END
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,7 @@
  *     Set the value of b->err appropriately.
  */
 int bson_check_field_name( bson *b, const char *string,
-                           const int length );
+                           const size_t length );
 
 /**
  * Check that a string is valid UTF8. Sets the buffer bit field appropriately.
@@ -48,7 +48,7 @@
  *     Sets b->err on error.
  */
 bson_bool_t bson_check_string( bson *b, const char *string,
-                               const int length );
+                               const size_t length );
 
 MONGO_EXTERN_C_END
 #endif
```
