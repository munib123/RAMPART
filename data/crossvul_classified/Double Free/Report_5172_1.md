# CrossVul Fix Pair: Double Free in c
**Pair ID:** 5172_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5172_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 1079-1119 of the vulnerable file.

			case ST_BINARY:
				if (Z_STRLEN_P(ent->data) == 0) {
					STR_FREE(Z_STRVAL_P(ent->data));
					Z_STRVAL_P(ent->data) = estrndup(s, len + 1);
				} else {
					Z_STRVAL_P(ent->data) = erealloc(Z_STRVAL_P(ent->data), Z_STRLEN_P(ent->data) + len + 1);
					memcpy(Z_STRVAL_P(ent->data) + Z_STRLEN_P(ent->data), s, len);
				}
				Z_STRLEN_P(ent->data) += len;
				Z_STRVAL_P(ent->data)[Z_STRLEN_P(ent->data)] = '\0';
				break;

			case ST_NUMBER:
				Z_TYPE_P(ent->data) = IS_STRING;
				Z_STRLEN_P(ent->data) = len;
				Z_STRVAL_P(ent->data) = estrndup(s, len);
				convert_scalar_to_number(ent->data TSRMLS_CC);
				break;

			case ST_BOOLEAN:
				if (!strcmp(s, "true")) {
					Z_LVAL_P(ent->data) = 1;
				} else if (!strcmp(s, "false")) {
					Z_LVAL_P(ent->data) = 0;
				} else {
					zval_ptr_dtor(&ent->data);
					if (ent->varname) {
						efree(ent->varname);
					}
					ent->data = NULL;
				}
				break;

			case ST_DATETIME: {
				char *tmp;

				tmp = emalloc(len + 1);
				memcpy(tmp, s, len);
				tmp[len] = '\0';

				Z_LVAL_P(ent->data) = php_parse_date(tmp, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1096,6 +1096,9 @@
 				break;
 
 			case ST_BOOLEAN:
+				if(!ent->data) {
+					break;
+				}
 				if (!strcmp(s, "true")) {
 					Z_LVAL_P(ent->data) = 1;
 				} else if (!strcmp(s, "false")) {
@@ -1104,6 +1107,7 @@
 					zval_ptr_dtor(&ent->data);
 					if (ent->varname) {
 						efree(ent->varname);
+						ent->varname = NULL;
 					}
 					ent->data = NULL;
 				}
```
