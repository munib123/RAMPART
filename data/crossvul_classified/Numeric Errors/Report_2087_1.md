# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2087_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2087_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1521-1563 of the vulnerable file.

	HashPosition pos;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ra", &IM, &styles) == FAILURE)  {
		return;
	}

	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);

	/* copy the style values in the stylearr */
	stylearr = safe_emalloc(sizeof(int), zend_hash_num_elements(HASH_OF(styles)), 0);

	zend_hash_internal_pointer_reset_ex(HASH_OF(styles), &pos);

	for (index = 0;; zend_hash_move_forward_ex(HASH_OF(styles), &pos))	{
		zval ** item;

		if (zend_hash_get_current_data_ex(HASH_OF(styles), (void **) &item, &pos) == FAILURE) {
			break;
		}

		convert_to_long_ex(item);

		stylearr[index++] = Z_LVAL_PP(item);
	}

	gdImageSetStyle(im, stylearr, index);

	efree(stylearr);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto resource imagecreatetruecolor(int x_size, int y_size)
   Create a new true color image */
PHP_FUNCTION(imagecreatetruecolor)
{
	long x_size, y_size;
	gdImagePtr im;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &x_size, &y_size) == FAILURE) {
		return;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1538,9 +1538,15 @@
 			break;
 		}
 
-		convert_to_long_ex(item);
-
-		stylearr[index++] = Z_LVAL_PP(item);
+		if (Z_TYPE_PP(item) != IS_LONG) {
+			zval lval;
+			lval = **item;
+			zval_copy_ctor(&lval);
+			convert_to_long(&lval);
+			stylearr[index++] = Z_LVAL(lval);
+		} else {
+			stylearr[index++] = Z_LVAL_PP(item);
+		}
 	}
 
 	gdImageSetStyle(im, stylearr, index);
@@ -3346,14 +3352,26 @@
 
 	for (i = 0; i < npoints; i++) {
 		if (zend_hash_index_find(Z_ARRVAL_P(POINTS), (i * 2), (void **) &var) == SUCCESS) {
-			SEPARATE_ZVAL((var));
-			convert_to_long(*var);
-			points[i].x = Z_LVAL_PP(var);
+			if (Z_TYPE_PP(var) != IS_LONG) {
+				zval lval;
+				lval = **var;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				points[i].x = Z_LVAL(lval);
+			} else {
+				points[i].x = Z_LVAL_PP(var);
+			}
 		}
 		if (zend_hash_index_find(Z_ARRVAL_P(POINTS), (i * 2) + 1, (void **) &var) == SUCCESS) {
-			SEPARATE_ZVAL(var);
-			convert_to_long(*var);
-			points[i].y = Z_LVAL_PP(var);
+			if (Z_TYPE_PP(var) != IS_LONG) {
+				zval lval;
+				lval = **var;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				points[i].y = Z_LVAL(lval);
+			} else {
+				points[i].y = Z_LVAL_PP(var);
+			}
 		}
 	}
 
@@ -4859,9 +4877,15 @@
 
 			for (j=0; j<3; j++) {
 				if (zend_hash_index_find(Z_ARRVAL_PP(var), (j), (void **) &var2) == SUCCESS) {
-					SEPARATE_ZVAL(var2);
-					convert_to_double(*var2);
-					matrix[i][j] = (float)Z_DVAL_PP(var2);
+					if (Z_TYPE_PP(var2) != IS_DOUBLE) {
+						zval dval;
+						dval = **var;
+						zval_copy_ctor(&dval);
+						convert_to_double(&dval);
+						matrix[i][j] = (float)Z_DVAL(dval);
+					} else {
+						matrix[i][j] = (float)Z_DVAL_PP(var2);
+					}
 				} else {
 					php_error_docref(NULL TSRMLS_CC, E_WARNING, "You must have a 3x3 matrix");
 					RETURN_FALSE;
@@ -4954,28 +4978,60 @@
 	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
 
 	if (zend_hash_find(HASH_OF(z_rect), "x", sizeof("x"), (void **)&tmp) != FAILURE) {
-		rect.x = Z_LVAL_PP(tmp);
+		if (Z_TYPE_PP(tmp) != IS_LONG) {
+			zval lval;
+			lval = **tmp;
+			zval_copy_ctor(&lval);
+			convert_to_long(&lval);
+			rect.x = Z_LVAL(lval);
+		} else {
+			rect.x = Z_LVAL_PP(tmp);
+		}
 	} else {
 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing x position");
 		RETURN_FALSE;
 	}
 
 	if (zend_hash_find(HASH_OF(z_rect), "y", sizeof("x"), (void **)&tmp) != FAILURE) {
-		rect.y = Z_LVAL_PP(tmp);
+		if (Z_TYPE_PP(tmp) != IS_LONG) {
+			zval lval;
+			lval = **tmp;
+			zval_copy_ctor(&lval);
+			convert_to_long(&lval);
+			rect.y = Z_LVAL(lval);
+		} else {
+			rect.y = Z_LVAL_PP(tmp);
+		}
 	} else {
 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing y position");
 		RETURN_FALSE;
 	}
 
 	if (zend_hash_find(HASH_OF(z_rect), "width", sizeof("width"), (void **)&tmp) != FAILURE) {
-		rect.width = Z_LVAL_PP(tmp);
+		if (Z_TYPE_PP(tmp) != IS_LONG) {
+			zval lval;
+			lval = **tmp;
+			zval_copy_ctor(&lval);
+			convert_to_long(&lval);
+			rect.width = Z_LVAL(lval);
+		} else {
+			rect.width = Z_LVAL_PP(tmp);
+		}
 	} else {
 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing width");
 		RETURN_FALSE;
 	}
 
 	if (zend_hash_find(HASH_OF(z_rect), "height", sizeof("height"), (void **)&tmp) != FAILURE) {
-		rect.height = Z_LVAL_PP(tmp);
+		if (Z_TYPE_PP(tmp) != IS_LONG) {
+			zval lval;
+			lval = **tmp;
+			zval_copy_ctor(&lval);
+			convert_to_long(&lval);
+			rect.height = Z_LVAL(lval);
+		} else {
+			rect.height = Z_LVAL_PP(tmp);
+		}
 	} else {
 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing height");
 		RETURN_FALSE;
@@ -5124,8 +5180,13 @@
 					affine[i] = Z_DVAL_PP(zval_affine_elem);
 					break;
 				case IS_STRING:
-					convert_to_double_ex(zval_affine_elem);
-					affine[i] = Z_DVAL_PP(zval_affine_elem);
+					{
+						zval dval;
+						dval = **zval_affine_elem;
+						zval_copy_ctor(&dval);
+						convert_to_double(&dval);
+						affine[i] = Z_DVAL(dval);
+					}
 					break;
 				default:
 					php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid type for element %i", i);
@@ -5136,32 +5197,60 @@
 
 	if (z_rect != NULL) {
 		if (zend_hash_find(HASH_OF(z_rect), "x", sizeof("x"), (void **)&tmp) != FAILURE) {
-			convert_to_long_ex(tmp);
-			rect.x = Z_LVAL_PP(tmp);
+			if (Z_TYPE_PP(tmp) != IS_LONG) {
+				zval lval;
+				lval = **tmp;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				rect.x = Z_LVAL(lval);
+			} else {
+				rect.x = Z_LVAL_PP(tmp);
+			}
 		} else {
 			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing x position");
 			RETURN_FALSE;
 		}
 
 		if (zend_hash_find(HASH_OF(z_rect), "y", sizeof("x"), (void **)&tmp) != FAILURE) {
-			convert_to_long_ex(tmp);
-			rect.y = Z_LVAL_PP(tmp);
+			if (Z_TYPE_PP(tmp) != IS_LONG) {
+				zval lval;
+				lval = **tmp;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				rect.y = Z_LVAL(lval);
+			} else {
+				rect.y = Z_LVAL_PP(tmp);
+			}
 		} else {
 			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing y position");
 			RETURN_FALSE;
 		}
 
 		if (zend_hash_find(HASH_OF(z_rect), "width", sizeof("width"), (void **)&tmp) != FAILURE) {
-			convert_to_long_ex(tmp);
-			rect.width = Z_LVAL_PP(tmp);
+			if (Z_TYPE_PP(tmp) != IS_LONG) {
+				zval lval;
+				lval = **tmp;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				rect.width = Z_LVAL(lval);
+			} else {
+				rect.width = Z_LVAL_PP(tmp);
+			}
 		} else {
 			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing width");
 			RETURN_FALSE;
 		}
 
 		if (zend_hash_find(HASH_OF(z_rect), "height", sizeof("height"), (void **)&tmp) != FAILURE) {
-			convert_to_long_ex(tmp);
-			rect.height = Z_LVAL_PP(tmp);
+			if (Z_TYPE_PP(tmp) != IS_LONG) {
+				zval lval;
+				lval = **tmp;
+				zval_copy_ctor(&lval);
+				convert_to_long(&lval);
+				rect.height = Z_LVAL(lval);
+			} else {
+				rect.height = Z_LVAL_PP(tmp);
+			}
 		} else {
 			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing height");
 			RETURN_FALSE;
@@ -5211,16 +5300,30 @@
 				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Array expected as options");
 			}
 			if (zend_hash_find(HASH_OF(options), "x", sizeof("x"), (void **)&tmp) != FAILURE) {
-				convert_to_double_ex(tmp);
-				x = Z_DVAL_PP(tmp);
+				if (Z_TYPE_PP(tmp) != IS_DOUBLE) {
+					zval dval;
+					dval = **tmp;
+					zval_copy_ctor(&dval);
+					convert_to_double(&dval);
+					x = Z_DVAL(dval);
+				} else {
+					x = Z_DVAL_PP(tmp);
+				}
 			} else {
 				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing x position");
 				RETURN_FALSE;
 			}
 
 			if (zend_hash_find(HASH_OF(options), "y", sizeof("y"), (void **)&tmp) != FAILURE) {
-				convert_to_double_ex(tmp);
-				y = Z_DVAL_PP(tmp);
+				if (Z_TYPE_PP(tmp) != IS_DOUBLE) {
+					zval dval;
+					dval = **tmp;
+					zval_copy_ctor(&dval);
+					convert_to_double(&dval);
+					y = Z_DVAL(dval);
+				} else {
+					y = Z_DVAL_PP(tmp);
+				}
 			} else {
 				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing y position");
 				RETURN_FALSE;
@@ -5300,8 +5403,13 @@
 					m1[i] = Z_DVAL_PP(tmp);
 					break;
 				case IS_STRING:
-					convert_to_double_ex(tmp);
-					m1[i] = Z_DVAL_PP(tmp);
+					{
+						zval dval;
+						dval = **tmp;
+						zval_copy_ctor(&dval);
+						convert_to_double(&dval);
+						m1[i] = Z_DVAL(dval);
+					}
 					break;
 				default:
 					php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid type for element %i", i);
@@ -5317,8 +5425,13 @@
 					m2[i] = Z_DVAL_PP(tmp);
 					break;
 				case IS_STRING:
-					convert_to_double_ex(tmp);
-					m2[i] = Z_DVAL_PP(tmp);
+					{
+						zval dval;
+						dval = **tmp;
+						zval_copy_ctor(&dval);
+						convert_to_double(&dval);
+						m2[i] = Z_DVAL(dval);
+					}
 					break;
 				default:
 					php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid type for element %i", i);
```
