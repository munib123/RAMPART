# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5515_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5515_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 794-834 of the vulnerable file.

		ALLOC_ZVAL(ent.data);
		INIT_PZVAL(ent.data);
		Z_TYPE_P(ent.data) = IS_LONG;
		Z_LVAL_P(ent.data) = 0;
		wddx_stack_push((wddx_stack *)stack, &ent, sizeof(st_entry));
	} else if (!strcmp(name, EL_BOOLEAN)) {
		int i;

		if (atts) for (i = 0; atts[i]; i++) {
			if (!strcmp(atts[i], EL_VALUE) && atts[i+1] && atts[i+1][0]) {
				ent.type = ST_BOOLEAN;
				SET_STACK_VARNAME;

				ALLOC_ZVAL(ent.data);
				INIT_PZVAL(ent.data);
				Z_TYPE_P(ent.data) = IS_BOOL;
				wddx_stack_push((wddx_stack *)stack, &ent, sizeof(st_entry));
				php_wddx_process_data(user_data, atts[i+1], strlen(atts[i+1]));
				break;
			}
		}
	} else if (!strcmp(name, EL_NULL)) {
		ent.type = ST_NULL;
		SET_STACK_VARNAME;

		ALLOC_ZVAL(ent.data);
		INIT_PZVAL(ent.data);
		ZVAL_NULL(ent.data);

		wddx_stack_push((wddx_stack *)stack, &ent, sizeof(st_entry));
	} else if (!strcmp(name, EL_ARRAY)) {
		ent.type = ST_ARRAY;
		SET_STACK_VARNAME;

		ALLOC_ZVAL(ent.data);
		array_init(ent.data);
		INIT_PZVAL(ent.data);
		wddx_stack_push((wddx_stack *)stack, &ent, sizeof(st_entry));
	} else if (!strcmp(name, EL_STRUCT)) {
		ent.type = ST_STRUCT;
		SET_STACK_VARNAME;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -811,6 +811,11 @@
 				php_wddx_process_data(user_data, atts[i+1], strlen(atts[i+1]));
 				break;
 			}
+		} else {
+			ent.type = ST_BOOLEAN;
+			SET_STACK_VARNAME;
+			ZVAL_FALSE(&ent.data);
+			wddx_stack_push((wddx_stack *)stack, &ent, sizeof(st_entry));
 		}
 	} else if (!strcmp(name, EL_NULL)) {
 		ent.type = ST_NULL;
```
