# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5291_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5291_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 755-795 of the vulnerable file.

		return;
	}

	/* storage */
	s = p = (const unsigned char*)buf;
	PHP_VAR_UNSERIALIZE_INIT(var_hash);

	if (*p!= 'x' || *++p != ':') {
		goto outexcept;
	}
	++p;

	pcount = var_tmp_var(&var_hash);
	if (!php_var_unserialize(pcount, &p, s + buf_len, &var_hash) || Z_TYPE_P(pcount) != IS_LONG) {
		goto outexcept;
	}

	--p; /* for ';' */
	count = Z_LVAL_P(pcount);

	while (count-- > 0) {
		spl_SplObjectStorageElement *pelement;
		zend_string *hash;

		if (*p != ';') {
			goto outexcept;
		}
		++p;
		if(*p != 'O' && *p != 'C' && *p != 'r') {
			goto outexcept;
		}
		/* store reference to allow cross-references between different elements */
		if (!php_var_unserialize(&entry, &p, s + buf_len, &var_hash)) {
			goto outexcept;
		}
		if (Z_TYPE(entry) != IS_OBJECT) {
			zval_ptr_dtor(&entry);
			goto outexcept;
		}
		if (*p == ',') { /* new version has inf */
			++p;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,6 +772,9 @@
 	--p; /* for ';' */
 	count = Z_LVAL_P(pcount);
 
+	ZVAL_UNDEF(&entry);
+	ZVAL_UNDEF(&inf);
+
 	while (count-- > 0) {
 		spl_SplObjectStorageElement *pelement;
 		zend_string *hash;
@@ -785,10 +788,6 @@
 		}
 		/* store reference to allow cross-references between different elements */
 		if (!php_var_unserialize(&entry, &p, s + buf_len, &var_hash)) {
-			goto outexcept;
-		}
-		if (Z_TYPE(entry) != IS_OBJECT) {
-			zval_ptr_dtor(&entry);
 			goto outexcept;
 		}
 		if (*p == ',') { /* new version has inf */
@@ -797,8 +796,11 @@
 				zval_ptr_dtor(&entry);
 				goto outexcept;
 			}
-		} else {
-			ZVAL_UNDEF(&inf);
+		}
+		if (Z_TYPE(entry) != IS_OBJECT) {
+			zval_ptr_dtor(&entry);
+			zval_ptr_dtor(&inf);
+			goto outexcept;
 		}
 
 		hash = spl_object_storage_get_hash(intern, getThis(), &entry);
```
