# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 634_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `634_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 271-311 of the vulnerable file.

    case SQL_DESC_SCHEMA_NAME:
    case SQL_DESC_TABLE_NAME:
    case SQL_DESC_TYPE_NAME:
        isStrField = 1;
        break;
    default:
        isStrField = buffer_length != SQL_IS_POINTER && buffer_length != SQL_IS_INTEGER
            && buffer_length != SQL_IS_UINTEGER && buffer_length != SQL_IS_SMALLINT &&
            buffer_length != SQL_IS_USMALLINT;
    }
    
    if ( isStrField && buffer_length < 0 && buffer_length != SQL_NTS)
    {
        __post_internal_error( &descriptor -> error,
            ERROR_HY090, NULL,
            descriptor -> connection -> environment -> requested_version );

        return function_return_nodrv( SQL_HANDLE_DESC, descriptor, SQL_ERROR );
    }

    if ( field_identifier == SQL_DESC_COUNT && (SQLINTEGER)value < 0 )
    {
        __post_internal_error( &descriptor -> error,
                ERROR_07009, NULL,
                descriptor -> connection -> environment -> requested_version );

        return function_return_nodrv( SQL_HANDLE_DESC, descriptor, SQL_ERROR );
    }

    if ( field_identifier == SQL_DESC_PARAMETER_TYPE && value != SQL_PARAM_INPUT
        && value != SQL_PARAM_OUTPUT && value != SQL_PARAM_INPUT_OUTPUT &&
        value != SQL_PARAM_INPUT_OUTPUT_STREAM && value != SQL_PARAM_OUTPUT_STREAM )
    {
        __post_internal_error( &descriptor -> error,
                ERROR_HY105, NULL,
                descriptor -> connection -> environment -> requested_version );

        return function_return_nodrv( SQL_HANDLE_DESC, descriptor, SQL_ERROR );
    }

    if ( descriptor -> connection -> unicode_driver ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,7 +288,7 @@
         return function_return_nodrv( SQL_HANDLE_DESC, descriptor, SQL_ERROR );
     }
 
-    if ( field_identifier == SQL_DESC_COUNT && (SQLINTEGER)value < 0 )
+    if ( field_identifier == SQL_DESC_COUNT && (intptr_t)value < 0 )
     {
         __post_internal_error( &descriptor -> error,
                 ERROR_07009, NULL,
@@ -297,9 +297,9 @@
         return function_return_nodrv( SQL_HANDLE_DESC, descriptor, SQL_ERROR );
     }
 
-    if ( field_identifier == SQL_DESC_PARAMETER_TYPE && value != SQL_PARAM_INPUT
-        && value != SQL_PARAM_OUTPUT && value != SQL_PARAM_INPUT_OUTPUT &&
-        value != SQL_PARAM_INPUT_OUTPUT_STREAM && value != SQL_PARAM_OUTPUT_STREAM )
+    if ( field_identifier == SQL_DESC_PARAMETER_TYPE && (intptr_t)value != SQL_PARAM_INPUT
+        && (intptr_t)value != SQL_PARAM_OUTPUT && (intptr_t)value != SQL_PARAM_INPUT_OUTPUT &&
+        (intptr_t)value != SQL_PARAM_INPUT_OUTPUT_STREAM && (intptr_t)value != SQL_PARAM_OUTPUT_STREAM )
     {
         __post_internal_error( &descriptor -> error,
                 ERROR_HY105, NULL,
```
