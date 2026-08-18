# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5170_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5170_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 62-102 of the vulnerable file.


static void spl_filesystem_file_free_line(spl_filesystem_object *intern TSRMLS_DC) /* {{{ */
{
	if (intern->u.file.current_line) {
		efree(intern->u.file.current_line);
		intern->u.file.current_line = NULL;
	}
	if (intern->u.file.current_zval) {
		zval_ptr_dtor(&intern->u.file.current_zval);
		intern->u.file.current_zval = NULL;
	}
} /* }}} */

static void spl_filesystem_object_free_storage(void *object TSRMLS_DC) /* {{{ */
{
	spl_filesystem_object *intern = (spl_filesystem_object*)object;

	if (intern->oth_handler && intern->oth_handler->dtor) {
		intern->oth_handler->dtor(intern TSRMLS_CC);
	}
	
	zend_object_std_dtor(&intern->std TSRMLS_CC);
	
	if (intern->_path) {
		efree(intern->_path);
	}
	if (intern->file_name) {
		efree(intern->file_name);
	}
	switch(intern->type) {
	case SPL_FS_INFO:
		break;
	case SPL_FS_DIR:
		if (intern->u.dir.dirp) {
			php_stream_close(intern->u.dir.dirp);
			intern->u.dir.dirp = NULL;
		}
		if (intern->u.dir.sub_path) {
			efree(intern->u.dir.sub_path);
		}		
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,9 +79,9 @@
 	if (intern->oth_handler && intern->oth_handler->dtor) {
 		intern->oth_handler->dtor(intern TSRMLS_CC);
 	}
-	
+
 	zend_object_std_dtor(&intern->std TSRMLS_CC);
-	
+
 	if (intern->_path) {
 		efree(intern->_path);
 	}
@@ -98,7 +98,7 @@
 		}
 		if (intern->u.dir.sub_path) {
 			efree(intern->u.dir.sub_path);
-		}		
+		}
 		break;
 	case SPL_FS_FILE:
 		if (intern->u.file.stream) {
@@ -134,13 +134,13 @@
 } /* }}} */
 
 /* {{{ spl_ce_dir_object_new */
-/* creates the object by 
-   - allocating memory 
+/* creates the object by
+   - allocating memory
    - initializing the object members
    - storing the object
    - setting it's handlers
 
-   called from 
+   called from
    - clone
    - new
  */
@@ -313,7 +313,7 @@
 	/* avoid reference counting in debug mode, thus do it manually */
 	ZVAL_RESOURCE(&intern->u.file.zresource, php_stream_get_resource_id(intern->u.file.stream));
 	Z_SET_REFCOUNT(intern->u.file.zresource, 1);
-	
+
 	intern->u.file.delimiter = ',';
 	intern->u.file.enclosure = '"';
 	intern->u.file.escape = '\\';
@@ -325,7 +325,7 @@
 
 /* {{{ spl_filesystem_object_clone */
 /* Local zend_object_value creation (on stack)
-   Load the 'other' object 
+   Load the 'other' object
    Create a new empty object (See spl_filesystem_object_new_ex)
    Open the directory
    Clone other members (properties)
@@ -370,7 +370,7 @@
 		php_error_docref(NULL TSRMLS_CC, E_ERROR, "An object of class %s cannot be cloned", old_object->ce->name);
 		break;
 	}
-	
+
 	intern->file_class = source->file_class;
 	intern->info_class = source->info_class;
 	intern->oth = source->oth;
@@ -389,7 +389,7 @@
 void spl_filesystem_info_set_filename(spl_filesystem_object *intern, char *path, int len, int use_copy TSRMLS_DC) /* {{{ */
 {
 	char *p1, *p2;
-	
+
 	if (intern->file_name) {
 		efree(intern->file_name);
 	}
@@ -413,7 +413,7 @@
 	} else {
 		intern->_path_len = 0;
 	}
-	
+
 	if (intern->_path) {
 		efree(intern->_path);
 	}
@@ -459,7 +459,7 @@
 	} else {
 		spl_filesystem_info_set_filename(intern, file_path, file_path_len, use_copy TSRMLS_CC);
 	}
-	
+
 	zend_restore_error_handling(&error_handling TSRMLS_CC);
 	return intern;
 } /* }}} */
@@ -514,7 +514,7 @@
 
 		return_value->value.obj = spl_filesystem_object_new_ex(ce, &intern TSRMLS_CC);
 		Z_TYPE_P(return_value) = IS_OBJECT;
-	
+
 		spl_filesystem_object_get_file_name(source TSRMLS_CC);
 
 		if (ce->constructor->common.scope != spl_ce_SplFileObject) {
@@ -530,12 +530,12 @@
 			intern->file_name_len = source->file_name_len;
 			intern->_path = spl_filesystem_object_get_path(source, &intern->_path_len TSRMLS_CC);
 			intern->_path = estrndup(intern->_path, intern->_path_len);
-		
+
 			intern->u.file.open_mode = "r";
 			intern->u.file.open_mode_len = 1;
-		
-			if (ht && zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sbr", 
-					&intern->u.file.open_mode, &intern->u.file.open_mode_len, 
+
+			if (ht && zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sbr",
+					&intern->u.file.open_mode, &intern->u.file.open_mode_len,
 					&use_include_path, &intern->u.file.zcontext) == FAILURE) {
 				zend_restore_error_handling(&error_handling TSRMLS_CC);
 				intern->u.file.open_mode = NULL;
@@ -544,7 +544,7 @@
 				Z_TYPE_P(return_value) = IS_NULL;
 				return NULL;
 			}
-		
+
 			if (spl_filesystem_file_open(intern, use_include_path, 0 TSRMLS_CC) == FAILURE) {
 				zend_restore_error_handling(&error_handling TSRMLS_CC);
 				zval_dtor(return_value);
@@ -553,7 +553,7 @@
 			}
 		}
 		break;
-	case SPL_FS_DIR:	
+	case SPL_FS_DIR:
 		zend_restore_error_handling(&error_handling TSRMLS_CC);
 		zend_throw_exception_ex(spl_ce_RuntimeException, 0 TSRMLS_CC, "Operation not supported");
 		return NULL;
@@ -617,7 +617,7 @@
 	if (intern->file_name) {
 		pnstr = spl_gen_private_prop_name(spl_ce_SplFileInfo, "fileName", sizeof("fileName")-1, &pnlen TSRMLS_CC);
 		spl_filesystem_object_get_path(intern, &path_len TSRMLS_CC);
-		
+
 		if (path_len && path_len < intern->file_name_len) {
 			add_assoc_stringl_ex(&zrv, pnstr, pnlen+1, intern->file_name + path_len + 1, intern->file_name_len - (path_len + 1), 1);
 		} else {
@@ -665,13 +665,13 @@
 zend_function *spl_filesystem_object_get_method_check(zval **object_ptr, char *method, int method_len, const struct _zend_literal *key TSRMLS_DC) /* {{{ */
 {
 	spl_filesystem_object *fsobj = zend_object_store_get_object(*object_ptr TSRMLS_CC);
-	
+
 	if (fsobj->u.dir.entry.d_name[0] == '\0' && fsobj->orig_path == NULL) {
 		method = "_bad_state_ex";
 		method_len = sizeof("_bad_state_ex") - 1;
 		key = NULL;
 	}
-	
+
 	return zend_get_std_object_handlers()->get_method(object_ptr, method, method_len, key TSRMLS_CC);
 }
 /* }}} */
@@ -751,7 +751,7 @@
 SPL_METHOD(DirectoryIterator, rewind)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -769,7 +769,7 @@
 SPL_METHOD(DirectoryIterator, key)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -799,7 +799,7 @@
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
 	int skip_dots = SPL_HAS_FLAG(intern->flags, SPL_FILE_DIR_SKIPDOTS);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -859,7 +859,7 @@
 SPL_METHOD(DirectoryIterator, valid)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -875,7 +875,7 @@
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
 	char *path;
 	int path_len;
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -891,13 +891,13 @@
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
 	int path_len;
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
 
 	spl_filesystem_object_get_path(intern, &path_len TSRMLS_CC);
-	
+
 	if (path_len && path_len < intern->file_name_len) {
 		RETURN_STRINGL(intern->file_name + path_len + 1, intern->file_name_len - (path_len + 1), 1);
 	} else {
@@ -911,7 +911,7 @@
 SPL_METHOD(DirectoryIterator, getFilename)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -1019,7 +1019,7 @@
 
 	RETURN_STRINGL(fname, flen, 0);
 }
-/* }}}*/   
+/* }}}*/
 
 /* {{{ proto string DirectoryIterator::getBasename([string $suffix]) U
    Returns filename component of current dir entry */
@@ -1029,7 +1029,7 @@
 	char *suffix = 0, *fname;
 	int slen = 0;
 	size_t flen;
-	
+
 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &suffix, &slen) == FAILURE) {
 		return;
 	}
@@ -1065,7 +1065,7 @@
 SPL_METHOD(FilesystemIterator, key)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -1084,7 +1084,7 @@
 SPL_METHOD(FilesystemIterator, current)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -1107,7 +1107,7 @@
 SPL_METHOD(DirectoryIterator, isDot)
 {
 	spl_filesystem_object *intern = (spl_filesystem_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
-	
+
 	if (zend_parse_parameters_none() == FAILURE) {
 		return;
 	}
@@ -1121,8 +1121,8 @@
 /* zend_replace_error_handling() is used to throw exceptions in case
    the constructor fails. Here we use this to ensure the object
    has a valid directory resource.
-   
... (diff truncated)
```
