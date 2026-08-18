# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5260_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5260_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 942-983 of the vulnerable file.

		!strcmp(name, EL_RECORDSET) || !strcmp(name, EL_BINARY) ||
		!strcmp(name, EL_DATETIME)) {
		wddx_stack_top(stack, (void**)&ent1);

		if (!ent1->data) {
			if (stack->top > 1) {
				stack->top--;
			} else {
				stack->done = 1;
			}
			efree(ent1);
			return;
		}

		if (!strcmp(name, EL_BINARY)) {
			int new_len=0;
			unsigned char *new_str;

			new_str = php_base64_decode(Z_STRVAL_P(ent1->data), Z_STRLEN_P(ent1->data), &new_len);
			STR_FREE(Z_STRVAL_P(ent1->data));
			Z_STRVAL_P(ent1->data) = new_str;
			Z_STRLEN_P(ent1->data) = new_len;
		}

		/* Call __wakeup() method on the object. */
		if (Z_TYPE_P(ent1->data) == IS_OBJECT) {
			zval *fname, *retval = NULL;

			MAKE_STD_ZVAL(fname);
			ZVAL_STRING(fname, "__wakeup", 1);

			call_user_function_ex(NULL, &ent1->data, fname, &retval, 0, 0, 0, NULL TSRMLS_CC);

			zval_dtor(fname);
			FREE_ZVAL(fname);
			if (retval) {
				zval_ptr_dtor(&retval);
			}
		}

		if (stack->top > 1) {
			stack->top--;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -959,8 +959,12 @@
 
 			new_str = php_base64_decode(Z_STRVAL_P(ent1->data), Z_STRLEN_P(ent1->data), &new_len);
 			STR_FREE(Z_STRVAL_P(ent1->data));
-			Z_STRVAL_P(ent1->data) = new_str;
-			Z_STRLEN_P(ent1->data) = new_len;
+			if (new_str) {
+				Z_STRVAL_P(ent1->data) = new_str;
+				Z_STRLEN_P(ent1->data) = new_len;
+			} else {
+				ZVAL_EMPTY_STRING(ent1->data);
+			}
 		}
 
 		/* Call __wakeup() method on the object. */
```
