# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 341_9
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `341_9`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 132-172 of the vulnerable file.


	*reader = sc_ctx_get_reader(*ctx, reader_id);

	return SC_SUCCESS;
}

int read_file(struct sc_card *card, char *str_path, unsigned char **data, size_t *data_len)
{
	struct sc_path path;
	struct sc_file *file;
	unsigned char *p;
	int ok = 0;
	int r;
	size_t len;

	sc_format_path(str_path, &path);
	if (SC_SUCCESS != sc_select_file(card, &path, &file)) {
		goto err;
	}

	len = file ? file->size : 4096;
	p = realloc(*data, len);
	if (!p) {
		goto err;
	}
	*data = p;
	*data_len = len;

	r = sc_read_binary(card, 0, p, len, 0);
	if (r < 0)
		goto err;

	*data_len = r;
	ok = 1;

err:
	sc_file_free(file);

	return ok;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -149,7 +149,7 @@
 		goto err;
 	}
 
-	len = file ? file->size : 4096;
+	len = file && file->size > 0 ? file->size : 4096;
 	p = realloc(*data, len);
 	if (!p) {
 		goto err;
```
