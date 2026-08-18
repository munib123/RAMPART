# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3988_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3988_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1629-1669 of the vulnerable file.

	 * (".git\") or NTFS alternate streams (".git:") and could be used
	 * to write to the ".git" directory on Windows platforms.
	 */
	if (path[start] == '\\' || path[start] == ':')
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
	}

	return true;
}

GIT_INLINE(bool) verify_dotgit_ntfs_generic(const char *name, size_t len, const char *dotgit_name, size_t dotgit_len, const char *shortname_pfix)
{
	int i, saw_tilde;

	if (name[0] == '.' && len >= dotgit_len &&
	    !strncasecmp(name + 1, dotgit_name, dotgit_len)) {
		return !only_spaces_and_dots(name + dotgit_len + 1);
	}

	/* Detect the basic NTFS shortname with the first six chars */
	if (!strncasecmp(name, dotgit_name, 6) && name[6] == '~' &&
	    name[7] >= '1' && name[7] <= '4')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1646,7 +1646,7 @@
 	const char *c = path;
 
 	for (;; c++) {
-		if (*c == '\0')
+		if (*c == '\0' || *c == ':')
 			return true;
 		if (*c != ' ' && *c != '.')
 			return false;
```
