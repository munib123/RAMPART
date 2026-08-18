# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1520_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1520_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 2492-2533 of the vulnerable file.

		l = mbtowc(&wc, p, alen);
		if (l == (size_t)-1) {
			while (*p != '\0') {
				if (*p == '\\')
					*p = '/';
				++p;
			}
			break;
		}
		if (l == 1 && wc == L'\\')
			*p = '/';
		p += l;
		alen -= l;
	}
}
#endif

/*
 * Canonicalize the pathname.  In particular, this strips duplicate
 * '/' characters, '.' elements, and trailing '/'.  It also raises an
 * error for an empty path, a trailing '..' or (if _SECURE_NODOTDOT is
 * set) any '..' in the path.
 */
static int
cleanup_pathname(struct archive_write_disk *a)
{
	char *dest, *src;
	char separator = '\0';

	dest = src = a->name;
	if (*src == '\0') {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Invalid empty pathname");
		return (ARCHIVE_FAILED);
	}

#if defined(__CYGWIN__)
	cleanup_pathname_win(a);
#endif
	/* Skip leading '/'. */
	if (*src == '/')
		separator = *src++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2509,8 +2509,9 @@
 /*
  * Canonicalize the pathname.  In particular, this strips duplicate
  * '/' characters, '.' elements, and trailing '/'.  It also raises an
- * error for an empty path, a trailing '..' or (if _SECURE_NODOTDOT is
- * set) any '..' in the path.
+ * error for an empty path, a trailing '..', (if _SECURE_NODOTDOT is
+ * set) any '..' in the path or (if ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS
+ * is set) if the path is absolute.
  */
 static int
 cleanup_pathname(struct archive_write_disk *a)
@@ -2529,8 +2530,15 @@
 	cleanup_pathname_win(a);
 #endif
 	/* Skip leading '/'. */
-	if (*src == '/')
+	if (*src == '/') {
+		if (a->flags & ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS) {
+			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
+			                  "Path is absolute");
+			return (ARCHIVE_FAILED);
+		}
+
 		separator = *src++;
+	}
 
 	/* Scan the pathname one element at a time. */
 	for (;;) {
```
