# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2607_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2607_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 734-776 of the vulnerable file.

	db->fp = NULL;
	errno = saved_errno;
	return 0;
}

/*
 * Sort given db according to cmp function (usually compares uids)
 */
int
commonio_sort (struct commonio_db *db, int (*cmp) (const void *, const void *))
{
	struct commonio_entry **entries, *ptr;
	size_t n = 0, i;
#if KEEP_NIS_AT_END
	struct commonio_entry *nis = NULL;
#endif

	for (ptr = db->head;
	        (NULL != ptr)
#if KEEP_NIS_AT_END
	     && (NULL != ptr->line)
	     && (   ('+' != ptr->line[0])
	         && ('-' != ptr->line[0]))
#endif
	     ;
	     ptr = ptr->next) {
		n++;
	}
#if KEEP_NIS_AT_END
	if ((NULL != ptr) && (NULL != ptr->line)) {
		nis = ptr;
	}
#endif

	if (n <= 1) {
		return 0;
	}

	entries = malloc (n * sizeof (struct commonio_entry *));
	if (entries == NULL) {
		return -1;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -751,16 +751,16 @@
 	for (ptr = db->head;
 	        (NULL != ptr)
 #if KEEP_NIS_AT_END
-	     && (NULL != ptr->line)
-	     && (   ('+' != ptr->line[0])
-	         && ('-' != ptr->line[0]))
+	     && ((NULL == ptr->line)
+	         || (('+' != ptr->line[0])
+	             && ('-' != ptr->line[0])))
 #endif
 	     ;
 	     ptr = ptr->next) {
 		n++;
 	}
 #if KEEP_NIS_AT_END
-	if ((NULL != ptr) && (NULL != ptr->line)) {
+	if (NULL != ptr) {
 		nis = ptr;
 	}
 #endif
```
