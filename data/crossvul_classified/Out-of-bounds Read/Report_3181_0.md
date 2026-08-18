# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3181_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3181_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1479-1519 of the vulnerable file.

			super_name = dex_class_super_name (bin, c);
			if (dexdump) { 
				rbin->cb_printf ("Class #%d            -\n", i);
			}
			parse_class (arch, bin, c, i, methods, &sym_count);
			free (class_name);
			free (super_name);
		}
	}

	if (methods) {
		int import_count = 0;
		int sym_count = bin->methods_list->length;

		for (i = 0; i < bin->header.method_size; i++) {
			int len = 0;
			if (methods[i]) {
				continue;
			}

			if (bin->methods[i].class_id > bin->header.types_size - 1) {
				continue;
			}

			if (is_class_idx_in_code_classes(bin, bin->methods[i].class_id)) {
				continue;
			}

			char *class_name = getstr (
				bin, bin->types[bin->methods[i].class_id]
						.descriptor_id);
			if (!class_name) {
				free (class_name);
				continue;
			}
			len = strlen (class_name);
			if (len < 1) {
				continue;
			}
			class_name[len - 1] = 0; // remove last char ";"
			char *method_name = dex_method_name (bin, i);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1496,7 +1496,7 @@
 				continue;
 			}
 
-			if (bin->methods[i].class_id > bin->header.types_size - 1) {
+			if (bin->methods[i].class_id > bin->header.types_size) {
 				continue;
 			}
 
```
