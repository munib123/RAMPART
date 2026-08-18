# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5082_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5082_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 48-90 of the vulnerable file.

#define PRIVATE_PREFIX "x"
#define DISP_NAME "name"

#define MAX_NO_VARIANT  15
#define MAX_NO_EXTLANG  3
#define MAX_NO_PRIVATE  15
#define MAX_NO_LOOKUP_LANG_TAG  100

#define LOC_NOT_FOUND 1

/* Sizes required for the strings "variant15" , "extlang3", "private12" etc. */
#define VARIANT_KEYNAME_LEN  11
#define EXTLANG_KEYNAME_LEN  10
#define PRIVATE_KEYNAME_LEN  11

/* Based on IANA registry at the time of writing this code
*
*/
static const char * const LOC_GRANDFATHERED[] = {
	"art-lojban",		"i-klingon",		"i-lux",			"i-navajo",		"no-bok",		"no-nyn",
	"cel-gaulish",		"en-GB-oed",		"i-ami", 		
	"i-bnn",		"i-default",		"i-enochian",	
	"i-mingo",		"i-pwn", 		"i-tao", 
	"i-tay",		"i-tsu",		"sgn-BE-fr",
	"sgn-BE-nl",		"sgn-CH-de", 		"zh-cmn",
 	"zh-cmn-Hans", 		"zh-cmn-Hant",		"zh-gan" ,
	"zh-guoyu", 		"zh-hakka", 		"zh-min",
	"zh-min-nan", 		"zh-wuu", 		"zh-xiang",	
	"zh-yue",		NULL
};

/* Based on IANA registry at the time of writing this code
*  This array lists the preferred values for the grandfathered tags if applicable
*  This is in sync with the array LOC_GRANDFATHERED	 
*  e.g. the offsets of the grandfathered tags match the offset of the preferred  value
*/
static const int 		LOC_PREFERRED_GRANDFATHERED_LEN = 6;
static const char * const 	LOC_PREFERRED_GRANDFATHERED[]  = {
	"jbo",			"tlh",			"lb",
	"nv", 			"nb",			"nn",			
	NULL
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,26 +65,26 @@
 */
 static const char * const LOC_GRANDFATHERED[] = {
 	"art-lojban",		"i-klingon",		"i-lux",			"i-navajo",		"no-bok",		"no-nyn",
-	"cel-gaulish",		"en-GB-oed",		"i-ami", 		
-	"i-bnn",		"i-default",		"i-enochian",	
-	"i-mingo",		"i-pwn", 		"i-tao", 
+	"cel-gaulish",		"en-GB-oed",		"i-ami",
+	"i-bnn",		"i-default",		"i-enochian",
+	"i-mingo",		"i-pwn", 		"i-tao",
 	"i-tay",		"i-tsu",		"sgn-BE-fr",
 	"sgn-BE-nl",		"sgn-CH-de", 		"zh-cmn",
  	"zh-cmn-Hans", 		"zh-cmn-Hant",		"zh-gan" ,
 	"zh-guoyu", 		"zh-hakka", 		"zh-min",
-	"zh-min-nan", 		"zh-wuu", 		"zh-xiang",	
+	"zh-min-nan", 		"zh-wuu", 		"zh-xiang",
 	"zh-yue",		NULL
 };
 
 /* Based on IANA registry at the time of writing this code
 *  This array lists the preferred values for the grandfathered tags if applicable
-*  This is in sync with the array LOC_GRANDFATHERED	 
+*  This is in sync with the array LOC_GRANDFATHERED
 *  e.g. the offsets of the grandfathered tags match the offset of the preferred  value
 */
 static const int 		LOC_PREFERRED_GRANDFATHERED_LEN = 6;
 static const char * const 	LOC_PREFERRED_GRANDFATHERED[]  = {
 	"jbo",			"tlh",			"lb",
-	"nv", 			"nb",			"nn",			
+	"nv", 			"nb",			"nn",
 	NULL
 };
 
@@ -122,7 +122,7 @@
 /*}}}*/
 
 static char* getPreferredTag(const char* gf_tag)
-{ 
+{
 	char* result = NULL;
 	int grOffset = 0;
 
@@ -141,15 +141,15 @@
 }
 
 /* {{{
-* returns the position of next token for lookup 
+* returns the position of next token for lookup
 * or -1 if no token
-* strtokr equivalent search for token in reverse direction 
+* strtokr equivalent search for token in reverse direction
 */
 static int getStrrtokenPos(char* str, int savedPos)
 {
 	int result =-1;
 	int i;
-	
+
 	for(i=savedPos-1; i>=0; i--) {
 		if(isIDSeparator(*(str+i)) ){
 			/* delimiter found; check for singleton */
@@ -171,7 +171,7 @@
 /* }}} */
 
 /* {{{
-* returns the position of a singleton if present 
+* returns the position of a singleton if present
 * returns -1 if no singleton
 * strtok equivalent search for singleton
 */
@@ -180,7 +180,7 @@
 	int result =-1;
 	int i=0;
 	int len = 0;
-	
+
 	if( str && ((len=strlen(str))>0) ){
 		for( i=0; i<len ; i++){
 			if( isIDSeparator(*(str+i)) ){
@@ -198,7 +198,7 @@
 				}
 			}
 		}/* end of for */
-		
+
 	}
 	return result;
 }
@@ -224,7 +224,7 @@
 PHP_NAMED_FUNCTION(zif_locale_set_default)
 {
 	char* locale_name = NULL;
-	int   len=0;	
+	int   len=0;
 
 	if(zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC,  "s",
 		&locale_name ,&len ) == FAILURE)
@@ -240,14 +240,14 @@
 		len = strlen(locale_name);
 	}
 
-	zend_alter_ini_entry(LOCALE_INI_NAME, sizeof(LOCALE_INI_NAME), locale_name, len, PHP_INI_USER, PHP_INI_STAGE_RUNTIME);	
+	zend_alter_ini_entry(LOCALE_INI_NAME, sizeof(LOCALE_INI_NAME), locale_name, len, PHP_INI_USER, PHP_INI_STAGE_RUNTIME);
 
 	RETURN_TRUE;
 }
 /* }}} */
 
 /* {{{
-* Gets the value from ICU 
+* Gets the value from ICU
 * common code shared by get_primary_language,get_script or get_region or get_variant
 * result = 0 if error, 1 if successful , -1 if no value
 */
@@ -284,7 +284,7 @@
 			}
 		}
 
-		singletonPos = getSingletonPos( loc_name );	
+		singletonPos = getSingletonPos( loc_name );
 		if( singletonPos == 0){
 			/* singleton at start of script, region , variant etc.
 			 * or invalid singleton at start of language */
@@ -299,7 +299,7 @@
 	} /* end of if != LOC_CANONICAL_TAG */
 
 	if( mod_loc_name == NULL){
-		mod_loc_name = estrdup(loc_name );	
+		mod_loc_name = estrdup(loc_name );
 	}
 
 	/* Proceed to ICU */
@@ -326,6 +326,7 @@
 		if( U_FAILURE( status ) ) {
 			if( status == U_BUFFER_OVERFLOW_ERROR ) {
 				status = U_ZERO_ERROR;
+				buflen++; /* add space for \0 */
 				continue;
 			}
 
@@ -366,7 +367,7 @@
 * Gets the value from ICU , called when PHP userspace function is called
 * common code shared by get_primary_language,get_script or get_region or get_variant
 */
-static void get_icu_value_src_php( char* tag_name, INTERNAL_FUNCTION_PARAMETERS) 
+static void get_icu_value_src_php( char* tag_name, INTERNAL_FUNCTION_PARAMETERS)
 {
 
 	const char* loc_name        	= NULL;
@@ -422,37 +423,37 @@
 }
 /* }}} */
 
-/* {{{ proto static string Locale::getScript($locale) 
- * gets the script for the $locale 
+/* {{{ proto static string Locale::getScript($locale)
+ * gets the script for the $locale
  }}} */
-/* {{{ proto static string locale_get_script($locale) 
- * gets the script for the $locale 
+/* {{{ proto static string locale_get_script($locale)
+ * gets the script for the $locale
  */
-PHP_FUNCTION( locale_get_script ) 
+PHP_FUNCTION( locale_get_script )
 {
 	get_icu_value_src_php( LOC_SCRIPT_TAG , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
 /* }}} */
 
-/* {{{ proto static string Locale::getRegion($locale) 
- * gets the region for the $locale 
+/* {{{ proto static string Locale::getRegion($locale)
+ * gets the region for the $locale
  }}} */
-/* {{{ proto static string locale_get_region($locale) 
- * gets the region for the $locale 
+/* {{{ proto static string locale_get_region($locale)
+ * gets the region for the $locale
  */
-PHP_FUNCTION( locale_get_region ) 
+PHP_FUNCTION( locale_get_region )
 {
 	get_icu_value_src_php( LOC_REGION_TAG , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
 /* }}} */
 
-/* {{{ proto static string Locale::getPrimaryLanguage($locale) 
- * gets the primary language for the $locale 
+/* {{{ proto static string Locale::getPrimaryLanguage($locale)
+ * gets the primary language for the $locale
  }}} */
-/* {{{ proto static string locale_get_primary_language($locale) 
- * gets the primary language for the $locale 
+/* {{{ proto static string locale_get_primary_language($locale)
+ * gets the primary language for the $locale
  */
-PHP_FUNCTION(locale_get_primary_language ) 
+PHP_FUNCTION(locale_get_primary_language )
 {
 	get_icu_value_src_php( LOC_LANG_TAG , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
@@ -460,9 +461,9 @@
 
 
 /* {{{
- * common code shared by display_xyz functions to  get the value from ICU 
+ * common code shared by display_xyz functions to  get the value from ICU
  }}} */
-static void get_icu_disp_value_src_php( char* tag_name, INTERNAL_FUNCTION_PARAMETERS) 
+static void get_icu_disp_value_src_php( char* tag_name, INTERNAL_FUNCTION_PARAMETERS)
 {
 	const char* loc_name        	= NULL;
 	int         loc_name_len    	= 0;
@@ -488,7 +489,7 @@
 	intl_error_reset( NULL TSRMLS_CC );
 
 	if(zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "s|s",
-		&loc_name, &loc_name_len , 
+		&loc_name, &loc_name_len ,
 		&disp_loc_name ,&disp_loc_name_len ) == FAILURE)
 	{
 		spprintf(&msg , 0, "locale_get_display_%s : unable to parse input params", tag_name );
@@ -525,7 +526,7 @@
 	if( mod_loc_name==NULL ){
 		mod_loc_name = estrdup( loc_name );
 	}
-	
+
 	/* Check if disp_loc_name passed , if not use default locale */
 	if( !disp_loc_name){
 		disp_loc_name = estrdup(intl_locale_get_default(TSRMLS_C));
@@ -604,7 +605,7 @@
 /* {{{ proto static string get_display_name($locale[, $in_locale = null])
 * gets the name for the $locale in $in_locale or default_locale
 */
-PHP_FUNCTION(locale_get_display_name) 
+PHP_FUNCTION(locale_get_display_name)
 {
     get_icu_disp_value_src_php( DISP_NAME , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
@@ -616,7 +617,7 @@
 /* {{{ proto static string get_display_language($locale[, $in_locale = null])
 * gets the language for the $locale in $in_locale or default_locale
 */
-PHP_FUNCTION(locale_get_display_language) 
+PHP_FUNCTION(locale_get_display_language)
 {
     get_icu_disp_value_src_php( LOC_LANG_TAG , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
@@ -628,7 +629,7 @@
 /* {{{ proto static string get_display_script($locale, $in_locale = null)
 * gets the script for the $locale in $in_locale or default_locale
 */
-PHP_FUNCTION(locale_get_display_script) 
+PHP_FUNCTION(locale_get_display_script)
 {
     get_icu_disp_value_src_php( LOC_SCRIPT_TAG , INTERNAL_FUNCTION_PARAM_PASSTHRU );
 }
@@ -640,7 +641,7 @@
... (diff truncated)
```
