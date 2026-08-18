# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5280_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5280_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 420-460 of the vulnerable file.


	return elements;
}

#ifdef PHP_WIN32
# pragma optimize("", off)
#endif
static inline int object_common2(UNSERIALIZE_PARAMETER, long elements)
{
	zval *retval_ptr = NULL;
	zval fname;

	if (Z_TYPE_PP(rval) != IS_OBJECT) {
		return 0;
	}

	if (!process_nested_data(UNSERIALIZE_PASSTHRU, Z_OBJPROP_PP(rval), elements, 1)) {
	    /* We've got partially constructed object on our hands here. Wipe it. */
	    if(Z_TYPE_PP(rval) == IS_OBJECT) {
	       zend_hash_clean(Z_OBJPROP_PP(rval));
	    }
	    ZVAL_NULL(*rval);
		return 0;
	}

    if (Z_TYPE_PP(rval) != IS_OBJECT) {
        return 0;
    }

	if (Z_OBJCE_PP(rval) != PHP_IC_ENTRY &&
		zend_hash_exists(&Z_OBJCE_PP(rval)->function_table, "__wakeup", sizeof("__wakeup"))) {
		INIT_PZVAL(&fname);
		ZVAL_STRINGL(&fname, "__wakeup", sizeof("__wakeup") - 1, 0);
		BG(serialize_lock)++;
		call_user_function_ex(CG(function_table), rval, &fname, &retval_ptr, 0, 0, 1, NULL TSRMLS_CC);
		BG(serialize_lock)--;
	}

	if (retval_ptr) {
		zval_ptr_dtor(&retval_ptr);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -437,6 +437,7 @@
 	    /* We've got partially constructed object on our hands here. Wipe it. */
 	    if(Z_TYPE_PP(rval) == IS_OBJECT) {
 	       zend_hash_clean(Z_OBJPROP_PP(rval));
+	       zend_object_store_ctor_failed(*rval TSRMLS_CC);
 	    }
 	    ZVAL_NULL(*rval);
 		return 0;
@@ -491,7 +492,7 @@
 
 
 
-#line 495 "ext/standard/var_unserializer.c"
+#line 496 "ext/standard/var_unserializer.c"
 {
 	YYCTYPE yych;
 	static const unsigned char yybm[] = {
@@ -551,9 +552,9 @@
 	yych = *(YYMARKER = ++YYCURSOR);
 	if (yych == ':') goto yy95;
 yy3:
-#line 860 "ext/standard/var_unserializer.re"
+#line 861 "ext/standard/var_unserializer.re"
 	{ return 0; }
-#line 557 "ext/standard/var_unserializer.c"
+#line 558 "ext/standard/var_unserializer.c"
 yy4:
 	yych = *(YYMARKER = ++YYCURSOR);
 	if (yych == ':') goto yy89;
@@ -596,13 +597,13 @@
 	goto yy3;
 yy14:
 	++YYCURSOR;
-#line 854 "ext/standard/var_unserializer.re"
+#line 855 "ext/standard/var_unserializer.re"
 	{
 	/* this is the case where we have less data than planned */
 	php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Unexpected end of serialized data");
 	return 0; /* not sure if it should be 0 or 1 here? */
 }
-#line 606 "ext/standard/var_unserializer.c"
+#line 607 "ext/standard/var_unserializer.c"
 yy16:
 	yych = *++YYCURSOR;
 	goto yy3;
@@ -633,7 +634,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 707 "ext/standard/var_unserializer.re"
+#line 708 "ext/standard/var_unserializer.re"
 	{
 	size_t len, len2, len3, maxlen;
 	long elements;
@@ -780,7 +781,7 @@
 
 	return object_common2(UNSERIALIZE_PASSTHRU, elements);
 }
-#line 784 "ext/standard/var_unserializer.c"
+#line 785 "ext/standard/var_unserializer.c"
 yy25:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -805,7 +806,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 698 "ext/standard/var_unserializer.re"
+#line 699 "ext/standard/var_unserializer.re"
 	{
     if (!var_hash) return 0;
 
@@ -814,7 +815,7 @@
 	return object_common2(UNSERIALIZE_PASSTHRU,
 			object_common1(UNSERIALIZE_PASSTHRU, ZEND_STANDARD_CLASS_DEF_PTR));
 }
-#line 818 "ext/standard/var_unserializer.c"
+#line 819 "ext/standard/var_unserializer.c"
 yy32:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy33;
@@ -835,7 +836,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '{') goto yy18;
 	++YYCURSOR;
-#line 677 "ext/standard/var_unserializer.re"
+#line 678 "ext/standard/var_unserializer.re"
 	{
 	long elements = parse_iv(start + 2);
 	/* use iv() not uiv() in order to check data range */
@@ -856,7 +857,7 @@
 
 	return finish_nested_data(UNSERIALIZE_PASSTHRU);
 }
-#line 860 "ext/standard/var_unserializer.c"
+#line 861 "ext/standard/var_unserializer.c"
 yy39:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy40;
@@ -877,7 +878,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 642 "ext/standard/var_unserializer.re"
+#line 643 "ext/standard/var_unserializer.re"
 	{
 	size_t len, maxlen;
 	char *str;
@@ -912,7 +913,7 @@
 	ZVAL_STRINGL(*rval, str, len, 0);
 	return 1;
 }
-#line 916 "ext/standard/var_unserializer.c"
+#line 917 "ext/standard/var_unserializer.c"
 yy46:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy47;
@@ -933,7 +934,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 609 "ext/standard/var_unserializer.re"
+#line 610 "ext/standard/var_unserializer.re"
 	{
 	size_t len, maxlen;
 	char *str;
@@ -966,7 +967,7 @@
 	ZVAL_STRINGL(*rval, str, len, 1);
 	return 1;
 }
-#line 970 "ext/standard/var_unserializer.c"
+#line 971 "ext/standard/var_unserializer.c"
 yy53:
 	yych = *++YYCURSOR;
 	if (yych <= '/') {
@@ -1054,7 +1055,7 @@
 	}
 yy63:
 	++YYCURSOR;
-#line 599 "ext/standard/var_unserializer.re"
+#line 600 "ext/standard/var_unserializer.re"
 	{
 #if SIZEOF_LONG == 4
 use_double:
@@ -1064,7 +1065,7 @@
 	ZVAL_DOUBLE(*rval, zend_strtod((const char *)start + 2, NULL));
 	return 1;
 }
-#line 1068 "ext/standard/var_unserializer.c"
+#line 1069 "ext/standard/var_unserializer.c"
 yy65:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1123,7 +1124,7 @@
 	yych = *++YYCURSOR;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 584 "ext/standard/var_unserializer.re"
+#line 585 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
@@ -1138,7 +1139,7 @@
 
 	return 1;
 }
-#line 1142 "ext/standard/var_unserializer.c"
+#line 1143 "ext/standard/var_unserializer.c"
 yy76:
 	yych = *++YYCURSOR;
 	if (yych == 'N') goto yy73;
@@ -1165,7 +1166,7 @@
 	if (yych <= '9') goto yy79;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 557 "ext/standard/var_unserializer.re"
+#line 558 "ext/standard/var_unserializer.re"
 	{
 #if SIZEOF_LONG == 4
 	int digits = YYCURSOR - start - 3;
@@ -1192,7 +1193,7 @@
 	ZVAL_LONG(*rval, parse_iv(start + 2));
 	return 1;
 }
-#line 1196 "ext/standard/var_unserializer.c"
+#line 1197 "ext/standard/var_unserializer.c"
 yy83:
 	yych = *++YYCURSOR;
 	if (yych <= '/') goto yy18;
@@ -1200,24 +1201,24 @@
 	yych = *++YYCURSOR;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 550 "ext/standard/var_unserializer.re"
+#line 551 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
 	ZVAL_BOOL(*rval, parse_iv(start + 2));
 	return 1;
 }
-#line 1211 "ext/standard/var_unserializer.c"
+#line 1212 "ext/standard/var_unserializer.c"
 yy87:
 	++YYCURSOR;
-#line 543 "ext/standard/var_unserializer.re"
+#line 544 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
 	ZVAL_NULL(*rval);
 	return 1;
 }
-#line 1221 "ext/standard/var_unserializer.c"
+#line 1222 "ext/standard/var_unserializer.c"
 yy89:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1240,7 +1241,7 @@
 	if (yych <= '9') goto yy91;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 520 "ext/standard/var_unserializer.re"
+#line 521 "ext/standard/var_unserializer.re"
 	{
 	long id;
 
@@ -1263,7 +1264,7 @@
 
 	return 1;
 }
-#line 1267 "ext/standard/var_unserializer.c"
+#line 1268 "ext/standard/var_unserializer.c"
 yy95:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1286,7 +1287,7 @@
 	if (yych <= '9') goto yy97;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 499 "ext/standard/var_unserializer.re"
+#line 500 "ext/standard/var_unserializer.re"
 	{
 	long id;
 
@@ -1307,9 +1308,9 @@
 
 	return 1;
 }
-#line 1311 "ext/standard/var_unserializer.c"
-}
-#line 862 "ext/standard/var_unserializer.re"
+#line 1312 "ext/standard/var_unserializer.c"
+}
+#line 863 "ext/standard/var_unserializer.re"
 
 
 	return 0;
```
