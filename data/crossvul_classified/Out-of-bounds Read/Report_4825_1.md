# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4825_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4825_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 388-428 of the vulnerable file.

		zend_error(E_WARNING, "Insufficient data for unserializing - %ld required, %ld present", datalen, (long)(max - (*p)));
		return 0;
	}

	if (ce->unserialize == NULL) {
		zend_error(E_WARNING, "Class %s has no unserializer", ce->name);
		object_init_ex(*rval, ce);
	} else if (ce->unserialize(rval, ce, (const unsigned char*)*p, datalen, (zend_unserialize_data *)var_hash TSRMLS_CC) != SUCCESS) {
		return 0;
	}

	(*p) += datalen;

	return finish_nested_data(UNSERIALIZE_PASSTHRU);
}

static inline long object_common1(UNSERIALIZE_PARAMETER, zend_class_entry *ce)
{
	long elements;

	elements = parse_iv2((*p) + 2, p);

	(*p) += 2;

	if (ce->serialize == NULL) {
		object_init_ex(*rval, ce);
	} else {
		/* If this class implements Serializable, it should not land here but in object_custom(). The passed string
		obviously doesn't descend from the regular serializer. */
		zend_error(E_WARNING, "Erroneous data format for unserializing '%s'", ce->name);
		return 0;
	}

	return elements;
}

#ifdef PHP_WIN32
# pragma optimize("", off)
#endif
static inline int object_common2(UNSERIALIZE_PARAMETER, long elements)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -405,6 +405,11 @@
 {
 	long elements;
 
+	if( *p >= max - 2) {
+		zend_error(E_WARNING, "Bad unserialize data");
+		return -1;
+	}
+
 	elements = parse_iv2((*p) + 2, p);
 
 	(*p) += 2;
@@ -415,7 +420,7 @@
 		/* If this class implements Serializable, it should not land here but in object_custom(). The passed string
 		obviously doesn't descend from the regular serializer. */
 		zend_error(E_WARNING, "Erroneous data format for unserializing '%s'", ce->name);
-		return 0;
+		return -1;
 	}
 
 	return elements;
@@ -492,7 +497,7 @@
 
 
 
-#line 496 "ext/standard/var_unserializer.c"
+#line 501 "ext/standard/var_unserializer.c"
 {
 	YYCTYPE yych;
 	static const unsigned char yybm[] = {
@@ -552,9 +557,9 @@
 	yych = *(YYMARKER = ++YYCURSOR);
 	if (yych == ':') goto yy95;
 yy3:
-#line 861 "ext/standard/var_unserializer.re"
+#line 875 "ext/standard/var_unserializer.re"
 	{ return 0; }
-#line 558 "ext/standard/var_unserializer.c"
+#line 563 "ext/standard/var_unserializer.c"
 yy4:
 	yych = *(YYMARKER = ++YYCURSOR);
 	if (yych == ':') goto yy89;
@@ -597,13 +602,13 @@
 	goto yy3;
 yy14:
 	++YYCURSOR;
-#line 855 "ext/standard/var_unserializer.re"
+#line 869 "ext/standard/var_unserializer.re"
 	{
 	/* this is the case where we have less data than planned */
 	php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Unexpected end of serialized data");
 	return 0; /* not sure if it should be 0 or 1 here? */
 }
-#line 607 "ext/standard/var_unserializer.c"
+#line 612 "ext/standard/var_unserializer.c"
 yy16:
 	yych = *++YYCURSOR;
 	goto yy3;
@@ -634,7 +639,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 708 "ext/standard/var_unserializer.re"
+#line 717 "ext/standard/var_unserializer.re"
 	{
 	size_t len, len2, len3, maxlen;
 	long elements;
@@ -774,6 +779,11 @@
 
 	elements = object_common1(UNSERIALIZE_PASSTHRU, ce);
 
+	if (elements < 0) {
+	   efree(class_name);
+	   return 0;
+	}
+
 	if (incomplete_class) {
 		php_store_class_name(*rval, class_name, len2);
 	}
@@ -781,7 +791,7 @@
 
 	return object_common2(UNSERIALIZE_PASSTHRU, elements);
 }
-#line 785 "ext/standard/var_unserializer.c"
+#line 795 "ext/standard/var_unserializer.c"
 yy25:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -806,16 +816,20 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 699 "ext/standard/var_unserializer.re"
+#line 704 "ext/standard/var_unserializer.re"
 	{
+	long elements;
     if (!var_hash) return 0;
 
 	INIT_PZVAL(*rval);
 
-	return object_common2(UNSERIALIZE_PASSTHRU,
-			object_common1(UNSERIALIZE_PASSTHRU, ZEND_STANDARD_CLASS_DEF_PTR));
-}
-#line 819 "ext/standard/var_unserializer.c"
+	elements = object_common1(UNSERIALIZE_PASSTHRU, ZEND_STANDARD_CLASS_DEF_PTR);
+	if (elements < 0) {
+		return 0;
+	}
+	return object_common2(UNSERIALIZE_PASSTHRU, elements);
+}
+#line 833 "ext/standard/var_unserializer.c"
 yy32:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy33;
@@ -836,7 +850,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '{') goto yy18;
 	++YYCURSOR;
-#line 678 "ext/standard/var_unserializer.re"
+#line 683 "ext/standard/var_unserializer.re"
 	{
 	long elements = parse_iv(start + 2);
 	/* use iv() not uiv() in order to check data range */
@@ -857,7 +871,7 @@
 
 	return finish_nested_data(UNSERIALIZE_PASSTHRU);
 }
-#line 861 "ext/standard/var_unserializer.c"
+#line 875 "ext/standard/var_unserializer.c"
 yy39:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy40;
@@ -878,7 +892,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 643 "ext/standard/var_unserializer.re"
+#line 648 "ext/standard/var_unserializer.re"
 	{
 	size_t len, maxlen;
 	char *str;
@@ -913,7 +927,7 @@
 	ZVAL_STRINGL(*rval, str, len, 0);
 	return 1;
 }
-#line 917 "ext/standard/var_unserializer.c"
+#line 931 "ext/standard/var_unserializer.c"
 yy46:
 	yych = *++YYCURSOR;
 	if (yych == '+') goto yy47;
@@ -934,7 +948,7 @@
 	yych = *++YYCURSOR;
 	if (yych != '"') goto yy18;
 	++YYCURSOR;
-#line 610 "ext/standard/var_unserializer.re"
+#line 615 "ext/standard/var_unserializer.re"
 	{
 	size_t len, maxlen;
 	char *str;
@@ -967,7 +981,7 @@
 	ZVAL_STRINGL(*rval, str, len, 1);
 	return 1;
 }
-#line 971 "ext/standard/var_unserializer.c"
+#line 985 "ext/standard/var_unserializer.c"
 yy53:
 	yych = *++YYCURSOR;
 	if (yych <= '/') {
@@ -1055,7 +1069,7 @@
 	}
 yy63:
 	++YYCURSOR;
-#line 600 "ext/standard/var_unserializer.re"
+#line 605 "ext/standard/var_unserializer.re"
 	{
 #if SIZEOF_LONG == 4
 use_double:
@@ -1065,7 +1079,7 @@
 	ZVAL_DOUBLE(*rval, zend_strtod((const char *)start + 2, NULL));
 	return 1;
 }
-#line 1069 "ext/standard/var_unserializer.c"
+#line 1083 "ext/standard/var_unserializer.c"
 yy65:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1124,7 +1138,7 @@
 	yych = *++YYCURSOR;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 585 "ext/standard/var_unserializer.re"
+#line 590 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
@@ -1139,7 +1153,7 @@
 
 	return 1;
 }
-#line 1143 "ext/standard/var_unserializer.c"
+#line 1157 "ext/standard/var_unserializer.c"
 yy76:
 	yych = *++YYCURSOR;
 	if (yych == 'N') goto yy73;
@@ -1166,7 +1180,7 @@
 	if (yych <= '9') goto yy79;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 558 "ext/standard/var_unserializer.re"
+#line 563 "ext/standard/var_unserializer.re"
 	{
 #if SIZEOF_LONG == 4
 	int digits = YYCURSOR - start - 3;
@@ -1193,7 +1207,7 @@
 	ZVAL_LONG(*rval, parse_iv(start + 2));
 	return 1;
 }
-#line 1197 "ext/standard/var_unserializer.c"
+#line 1211 "ext/standard/var_unserializer.c"
 yy83:
 	yych = *++YYCURSOR;
 	if (yych <= '/') goto yy18;
@@ -1201,24 +1215,24 @@
 	yych = *++YYCURSOR;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 551 "ext/standard/var_unserializer.re"
+#line 556 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
 	ZVAL_BOOL(*rval, parse_iv(start + 2));
 	return 1;
 }
-#line 1212 "ext/standard/var_unserializer.c"
+#line 1226 "ext/standard/var_unserializer.c"
 yy87:
 	++YYCURSOR;
-#line 544 "ext/standard/var_unserializer.re"
+#line 549 "ext/standard/var_unserializer.re"
 	{
 	*p = YYCURSOR;
 	INIT_PZVAL(*rval);
 	ZVAL_NULL(*rval);
 	return 1;
 }
-#line 1222 "ext/standard/var_unserializer.c"
+#line 1236 "ext/standard/var_unserializer.c"
 yy89:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1241,7 +1255,7 @@
 	if (yych <= '9') goto yy91;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 521 "ext/standard/var_unserializer.re"
+#line 526 "ext/standard/var_unserializer.re"
 	{
 	long id;
 
@@ -1264,7 +1278,7 @@
 
 	return 1;
 }
-#line 1268 "ext/standard/var_unserializer.c"
+#line 1282 "ext/standard/var_unserializer.c"
 yy95:
 	yych = *++YYCURSOR;
 	if (yych <= ',') {
@@ -1287,7 +1301,7 @@
 	if (yych <= '9') goto yy97;
 	if (yych != ';') goto yy18;
 	++YYCURSOR;
-#line 500 "ext/standard/var_unserializer.re"
+#line 505 "ext/standard/var_unserializer.re"
 	{
 	long id;
 
@@ -1308,9 +1322,9 @@
 
 	return 1;
 }
-#line 1312 "ext/standard/var_unserializer.c"
-}
-#line 863 "ext/standard/var_unserializer.re"
+#line 1326 "ext/standard/var_unserializer.c"
+}
+#line 877 "ext/standard/var_unserializer.re"
 
 
 	return 0;
```
