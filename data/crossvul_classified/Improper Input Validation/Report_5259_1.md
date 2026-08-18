# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5259_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5259_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1106-1147 of the vulnerable file.

				if(!ent->data) {
					break;
				}
				if (!strcmp(s, "true")) {
					Z_LVAL_P(ent->data) = 1;
				} else if (!strcmp(s, "false")) {
					Z_LVAL_P(ent->data) = 0;
				} else {
					zval_ptr_dtor(&ent->data);
					if (ent->varname) {
						efree(ent->varname);
						ent->varname = NULL;
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
				/* date out of range < 1969 or > 2038 */
				if (Z_LVAL_P(ent->data) == -1) {
					Z_TYPE_P(ent->data) = IS_STRING;
					Z_STRLEN_P(ent->data) = len;
					Z_STRVAL_P(ent->data) = estrndup(s, len);
				}
				efree(tmp);
			}
				break;

			default:
				break;
		}
	}
}
/* }}} */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1123,18 +1123,26 @@
 			case ST_DATETIME: {
 				char *tmp;
 
-				tmp = emalloc(len + 1);
-				memcpy(tmp, s, len);
+				if (Z_TYPE_P(ent->data) == IS_STRING) {
+					tmp = safe_emalloc(Z_STRLEN_P(ent->data), 1, (size_t)len + 1);
+					memcpy(tmp, Z_STRVAL_P(ent->data), Z_STRLEN_P(ent->data));
+					memcpy(tmp + Z_STRLEN_P(ent->data), s, len);
+					len += Z_STRLEN_P(ent->data);
+					efree(Z_STRVAL_P(ent->data));
+					Z_TYPE_P(ent->data) = IS_LONG;
+				} else {
+					tmp = emalloc(len + 1);
+					memcpy(tmp, s, len);
+				}
 				tmp[len] = '\0';
 
 				Z_LVAL_P(ent->data) = php_parse_date(tmp, NULL);
 				/* date out of range < 1969 or > 2038 */
 				if (Z_LVAL_P(ent->data) == -1) {
-					Z_TYPE_P(ent->data) = IS_STRING;
-					Z_STRLEN_P(ent->data) = len;
-					Z_STRVAL_P(ent->data) = estrndup(s, len);
+					ZVAL_STRINGL(ent->data, tmp, len, 0);
+				} else {
+					efree(tmp);
 				}
-				efree(tmp);
 			}
 				break;
 
```
