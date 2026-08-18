# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5034_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5034_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1368-1409 of the vulnerable file.


	memset(pdev, 0, sizeof(*pdev));
	if ((dev = strchr(val, ',')) != NULL) {
		/*
		 * Device's major/minor are given in a specified format.
		 * Decode and pack it accordingly.
		 */
		*dev++ = '\0';
		if ((pack = pack_find(val)) == NULL) {
			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
			    "Unknown format `%s'", val);
			return ARCHIVE_WARN;
		}
		argc = 0;
		while ((p = la_strsep(&dev, ",")) != NULL) {
			if (*p == '\0') {
				archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
				    "Missing number");
				return ARCHIVE_WARN;
			}
			numbers[argc++] = (unsigned long)mtree_atol(&p);
			if (argc > MAX_PACK_ARGS) {
				archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
				    "Too many arguments");
				return ARCHIVE_WARN;
			}
		}
		if (argc < 2) {
			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
			    "Not enough arguments");
			return ARCHIVE_WARN;
		}
		result = (*pack)(argc, numbers, &error);
		if (error != NULL) {
			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
			    "%s", error);
			return ARCHIVE_WARN;
		}
	} else {
		/* file system raw value. */
		result = (dev_t)mtree_atol(&val);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1385,12 +1385,12 @@
 				    "Missing number");
 				return ARCHIVE_WARN;
 			}
-			numbers[argc++] = (unsigned long)mtree_atol(&p);
-			if (argc > MAX_PACK_ARGS) {
+			if (argc >= MAX_PACK_ARGS) {
 				archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
 				    "Too many arguments");
 				return ARCHIVE_WARN;
 			}
+			numbers[argc++] = (unsigned long)mtree_atol(&p);
 		}
 		if (argc < 2) {
 			archive_set_error(a, ARCHIVE_ERRNO_FILE_FORMAT,
```
