# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in c
**Pair ID:** 1286_1
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1286_1`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```c
Lines 98-147 of the vulnerable file.

        { .alg = alg_hs256, .text = "HS256" },
        { .alg = alg_hs384, .text = "HS384" },
        { .alg = alg_hs512, .text = "HS512" },
        { .alg = alg_ps256, .text = "PS256" },
        { .alg = alg_ps384, .text = "PS384" },
        { .alg = alg_ps512, .text = "PS512" },
        { .alg = alg_rs256, .text = "RS256" },
        { .alg = alg_rs384, .text = "RS384" },
        { .alg = alg_rs512, .text = "RS512" }
    };
    size_t count, i;
    count = sizeof( m ) / sizeof( struct alg_map );

    for( i = 0; i < count; i++ ) {
        if( !strcasecmp( alg_str, m[i].text ) ) {
            return m[i].alg;
        }
    }

    return -1;
}

static cjwt_alg_t __cjwt_alg_str_to_enum( const char *alg_str )
{
  int alg = cjwt_alg_str_to_enum (alg_str);

  if (alg >= 0)
		return alg;
	else
		return alg_none;
}


inline static void cjwt_delete_child_json( cJSON* j, const char* s )
{
    if( j && cJSON_HasObjectItem( j, s ) ) {
        cJSON_DeleteItemFromObject( j, s );
    }
}

static void cjwt_delete_public_claims( cJSON* val )
{
    cjwt_delete_child_json( val, "iss" );
    cjwt_delete_child_json( val, "sub" );
    cjwt_delete_child_json( val, "aud" );
    cjwt_delete_child_json( val, "jti" );
    cjwt_delete_child_json( val, "exp" );
    cjwt_delete_child_json( val, "nbf" );
    cjwt_delete_child_json( val, "iat" );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,16 +115,6 @@
     }
 
     return -1;
-}
-
-static cjwt_alg_t __cjwt_alg_str_to_enum( const char *alg_str )
-{
-  int alg = cjwt_alg_str_to_enum (alg_str);
-
-  if (alg >= 0)
-		return alg;
-	else
-		return alg_none;
 }
 
 
@@ -357,12 +347,14 @@
     if( sz_signed != out_size ) {
         cjwt_info( "Signature length mismatch: enc %d, signature %d\n",
                    ( int )sz_signed, ( int )out_size );
-        ret = -1;
+        ret = EINVAL;
         goto err_match;
     }
 
-    ret = CRYPTO_memcmp(
-              ( unsigned char* )signed_out, ( unsigned char* )signed_dec, out_size );
+    if( 0 != CRYPTO_memcmp(signed_out, signed_dec, out_size) ) {
+        ret = EINVAL;
+    }
+
 err_match:
     free( signed_dec );
 err_decode:
@@ -384,7 +376,8 @@
     cJSON *j_payload = cJSON_Parse( ( char* )p_decpl );
 
     if( !j_payload ) {
-        return ENOMEM;
+        // The data is probably not json vs. memory allocation error.
+        return EINVAL;
     }
 
     //extract data
@@ -562,6 +555,7 @@
 }
 
 static int cjwt_update_header( cjwt_t *p_cjwt, char *p_dechead )
+    // The data is probably not json vs. memory allocation error.
 {
     if( !p_cjwt || !p_dechead ) {
         return EINVAL;
@@ -571,7 +565,8 @@
     cJSON *j_header = cJSON_Parse( ( char* )p_dechead );
 
     if( !j_header ) {
-        return ENOMEM;
+        // The data is probably not json vs. memory allocation error.
+        return EINVAL;
     }
 
     cjwt_info( "Json  = %s\n", cJSON_Print( j_header ) );
@@ -586,7 +581,14 @@
     cJSON* j_alg = cJSON_GetObjectItem( j_header, "alg" );
 
     if( j_alg ) {
-        p_cjwt->header.alg = __cjwt_alg_str_to_enum( j_alg->valuestring );
+        int alg;
+
+        alg = cjwt_alg_str_to_enum( j_alg->valuestring );
+        if( -1 == alg ) {
+            cJSON_Delete( j_header );
+            return ENOTSUP;
+        }
+        p_cjwt->header.alg = alg;
     }
 
     //destroy cJSON object
@@ -711,7 +713,6 @@
     int ret = 0;
     char *payload, *signature;
     ( void )options; //suppressing unused parameter warning
-    ( void ) options;
 
     //validate inputs
     if( !encoded || !jwt ) {
```
