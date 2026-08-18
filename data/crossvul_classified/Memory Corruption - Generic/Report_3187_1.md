# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3187_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3187_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 247-287 of the vulnerable file.

	if (!mspack_handle)
		return -1;

	if (mspack_handle->type == FILETYPE_FMAP)
		return mspack_handle->offset;

	return (off_t) ftell(mspack_handle->f);
}

static void mspack_fmap_message(struct mspack_file *file, const char *fmt, ...)
{
	cli_dbgmsg("%s() %s\n", __func__, fmt);
}
static void *mspack_fmap_alloc(struct mspack_system *self, size_t num)
{
	return malloc(num);
}

static void mspack_fmap_free(void *mem)
{
	free(mem);
}

static void mspack_fmap_copy(void *src, void *dst, size_t num)
{
	memcpy(dst, src, num);
}

static struct mspack_system mspack_sys_fmap_ops = {
	.open = mspack_fmap_open,
	.close = mspack_fmap_close,
	.read = mspack_fmap_read,
	.write = mspack_fmap_write,
	.seek = mspack_fmap_seek,
	.tell = mspack_fmap_tell,
	.message = mspack_fmap_message,
	.alloc = mspack_fmap_alloc,
	.free = mspack_fmap_free,
	.copy = mspack_fmap_copy,
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -264,7 +264,11 @@
 
 static void mspack_fmap_free(void *mem)
 {
-	free(mem);
+    if(mem) {
+        free(mem);
+        mem = NULL;
+    }
+    return;
 }
 
 static void mspack_fmap_copy(void *src, void *dst, size_t num)
```
