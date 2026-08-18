# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 669_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `669_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1140-1180 of the vulnerable file.


		if( members_data_size > 0 )
		{
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: members trailing data:\n",
				 function );
				libcnotify_print_data(
				 &( record_data[ record_data_offset ] ),
				 members_data_size,
				 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
			}
#endif
			record_data_offset += members_data_size;
		}
	}
	if( user_sid_size != 0 )
	{
		if( libfvalue_value_type_initialize(
		     &( record_values->user_security_identifier ),
		     LIBFVALUE_VALUE_TYPE_NT_SECURITY_IDENTIFIER,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
			 "%s: unable to create user security identifier (SID) value.",
			 function );

			goto on_error;
		}
		if( libfvalue_value_set_data(
		     record_values->user_security_identifier,
		     &( record_data[ user_sid_offset ] ),
		     (size_t) user_sid_size,
		     LIBFVALUE_ENDIAN_LITTLE,
		     LIBFVALUE_VALUE_DATA_FLAG_MANAGED,
		     error ) != 1 )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1157,6 +1157,17 @@
 	}
 	if( user_sid_size != 0 )
 	{
+		if( user_sid_size > ( ( record_data_size - 4 ) - user_sid_offset ) )
+		{
+			libcerror_error_set(
+			 error,
+			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
+			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
+			 "%s: user SID data size value out of bounds.",
+			 function );
+
+			goto on_error;
+		}
 		if( libfvalue_value_type_initialize(
 		     &( record_values->user_security_identifier ),
 		     LIBFVALUE_VALUE_TYPE_NT_SECURITY_IDENTIFIER,
@@ -1218,6 +1229,17 @@
 	}
 	if( strings_size != 0 )
 	{
+		if( strings_size > ( ( record_data_size - 4 ) - strings_offset ) )
+		{
+			libcerror_error_set(
+			 error,
+			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
+			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
+			 "%s: strings size value out of bounds.",
+			 function );
+
+			goto on_error;
+		}
 #if defined( HAVE_DEBUG_OUTPUT )
 		if( libcnotify_verbose != 0 )
 		{
@@ -1285,6 +1307,17 @@
 	}
 	if( data_size != 0 )
 	{
+		if( data_size > ( ( record_data_size - 4 ) - data_offset ) )
+		{
+			libcerror_error_set(
+			 error,
+			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
+			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
+			 "%s: data size value out of bounds.",
+			 function );
+
+			goto on_error;
+		}
 #if defined( HAVE_DEBUG_OUTPUT )
 		if( libcnotify_verbose != 0 )
 		{
@@ -1292,7 +1325,7 @@
 			 "%s: data:\n",
 			 function );
 			libcnotify_print_data(
-			 &( record_data[ data_offset ] ),
+			 &( record_data[ record_data_offset ] ),
 			 (size_t) data_size,
 			 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
 		}
```
