# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 339_7
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `339_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 611-651 of the vulnerable file.

	if (sc_file_set_prop_attr(newf, src->prop_attr, src->prop_attr_len) < 0)
		goto err;
	if (sc_file_set_type_attr(newf, src->type_attr, src->type_attr_len) < 0)
		goto err;
	if (sc_file_set_content(newf, src->encoded_content, src->encoded_content_len) < 0)
		goto err;
	return;
err:
	sc_file_free(newf);
	*dest = NULL;
}

int sc_file_set_sec_attr(sc_file_t *file, const u8 *sec_attr,
			 size_t sec_attr_len)
{
	u8 *tmp;
	if (!sc_file_valid(file)) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (sec_attr == NULL) {
		if (file->sec_attr != NULL)
			free(file->sec_attr);
		file->sec_attr = NULL;
		file->sec_attr_len = 0;
		return 0;
	 }
	tmp = (u8 *) realloc(file->sec_attr, sec_attr_len);
	if (!tmp) {
		if (file->sec_attr)
			free(file->sec_attr);
		file->sec_attr     = NULL;
		file->sec_attr_len = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	file->sec_attr = tmp;
	memcpy(file->sec_attr, sec_attr, sec_attr_len);
	file->sec_attr_len = sec_attr_len;

	return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -628,7 +628,7 @@
 		return SC_ERROR_INVALID_ARGUMENTS;
 	}
 
-	if (sec_attr == NULL) {
+	if (sec_attr == NULL || sec_attr_len) {
 		if (file->sec_attr != NULL)
 			free(file->sec_attr);
 		file->sec_attr = NULL;
```
