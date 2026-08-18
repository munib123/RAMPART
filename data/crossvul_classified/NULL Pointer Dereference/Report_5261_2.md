# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5261_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5261_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 929-969 of the vulnerable file.

	zend_class_entry 	**pce;
	zval				*obj;
	zval				*tmp;
	TSRMLS_FETCH();

/* OBJECTS_FIXME */
	if (stack->top == 0) {
		return;
	}

	if (!strcmp(name, EL_STRING) || !strcmp(name, EL_NUMBER) ||
		!strcmp(name, EL_BOOLEAN) || !strcmp(name, EL_NULL) ||
	  	!strcmp(name, EL_ARRAY) || !strcmp(name, EL_STRUCT) ||
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
			if (new_str) {
				Z_STRVAL_P(ent1->data) = new_str;
				Z_STRLEN_P(ent1->data) = new_len;
			} else {
				ZVAL_EMPTY_STRING(ent1->data);
			}
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -946,10 +946,10 @@
 		if (!ent1->data) {
 			if (stack->top > 1) {
 				stack->top--;
+				efree(ent1);
 			} else {
 				stack->done = 1;
 			}
-			efree(ent1);
 			return;
 		}
 
@@ -988,7 +988,7 @@
 			wddx_stack_top(stack, (void**)&ent2);
 
 			/* if non-existent field */
-			if (ent2->type == ST_FIELD && ent2->data == NULL) {
+			if (ent2->data == NULL) {
 				zval_ptr_dtor(&ent1->data);
 				efree(ent1);
 				return;
@@ -1179,9 +1179,13 @@
 
 	if (stack.top == 1) {
 		wddx_stack_top(&stack, (void**)&ent);
-		*return_value = *(ent->data);
-		zval_copy_ctor(return_value);
-		retval = SUCCESS;
+		if(ent->data == NULL) {
+			retval = FAILURE;
+		} else {
+			*return_value = *(ent->data);
+			zval_copy_ctor(return_value);
+			retval = SUCCESS;
+		}
 	} else {
 		retval = FAILURE;
 	}
```
