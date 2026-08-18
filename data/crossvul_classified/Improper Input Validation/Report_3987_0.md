# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3987_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3987_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1607-1648 of the vulnerable file.

	git_buf *reserved = git_repository__reserved_names_win32;
	size_t reserved_len = git_repository__reserved_names_win32_len;
	size_t start = 0, i;

	if (repo)
		git_repository__reserved_names(&reserved, &reserved_len, repo, true);

	for (i = 0; i < reserved_len; i++) {
		git_buf *r = &reserved[i];

		if (len >= r->size &&
			strncasecmp(path, r->ptr, r->size) == 0) {
			start = r->size;
			break;
		}
	}

	if (!start)
		return true;

	/* Reject paths like ".git\" */
	if (path[start] == '\\')
		return false;

	/* Reject paths like '.git ' or '.git.' */
	for (i = start; i < len; i++) {
		if (path[i] != ' ' && path[i] != '.')
			return true;
	}

	return false;
}

GIT_INLINE(bool) only_spaces_and_dots(const char *path)
{
	const char *c = path;

	for (;; c++) {
		if (*c == '\0')
			return true;
		if (*c != ' ' && *c != '.')
			return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1624,8 +1624,12 @@
 	if (!start)
 		return true;
 
-	/* Reject paths like ".git\" */
-	if (path[start] == '\\')
+	/*
+	 * Reject paths that start with Windows-style directory separators
+	 * (".git\") or NTFS alternate streams (".git:") and could be used
+	 * to write to the ".git" directory on Windows platforms.
+	 */
+	if (path[start] == '\\' || path[start] == ':')
 		return false;
 
 	/* Reject paths like '.git ' or '.git.' */
```
