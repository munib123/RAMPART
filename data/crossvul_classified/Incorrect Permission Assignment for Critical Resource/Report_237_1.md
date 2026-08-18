# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 237_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `237_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 237-277 of the vulnerable file.

char *M_fs_path_join_parts(const M_list_str_t *path, M_fs_system_t sys_type)
{
	M_list_str_t *parts;
	const char   *part;
	char         *out;
	size_t        len;
	size_t        i;
	size_t        count;

	if (path == NULL) {
		return NULL;
	}
	len = M_list_str_len(path);
	if (len == 0) {
		return NULL;
	}

	sys_type = M_fs_path_get_system_type(sys_type);

	/* Remove any empty parts (except for the first part which denotes an abs path on Unix
 	 * or a UNC path on Windows). */
	parts = M_list_str_duplicate(path);
	for (i=len-1; i>0; i--) {
		part = M_list_str_at(parts, i);
		if (part == NULL || *part == '\0') {
			M_list_str_remove_at(parts, i);
		}
	}

	len = M_list_str_len(parts);

	/* Join puts the sep between items. If there are no items then the sep
	 * won't be written. */
	part = M_list_str_at(parts, 0);
	if (len == 1 && (part == NULL || *part == '\0')) {
		M_list_str_destroy(parts);
		if (sys_type == M_FS_SYSTEM_WINDOWS) {
			return M_strdup("\\\\");
		}
		return M_strdup("/");
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,7 +254,7 @@
 	sys_type = M_fs_path_get_system_type(sys_type);
 
 	/* Remove any empty parts (except for the first part which denotes an abs path on Unix
- 	 * or a UNC path on Windows). */
+	 * or a UNC path on Windows). */
 	parts = M_list_str_duplicate(path);
 	for (i=len-1; i>0; i--) {
 		part = M_list_str_at(parts, i);
@@ -536,7 +536,7 @@
 	}
 
 	/* Hidden. Check if the first character of the last part of the path. Either the file or directory name itself
- 	 * starts with a '.'. */
+	 * starts with a '.'. */
 	path_parts = M_fs_path_componentize_path(path, M_FS_SYSTEM_UNIX);
 	len = M_list_str_len(path_parts);
 	if (len > 0) {
@@ -601,7 +601,23 @@
 	d = M_fs_path_mac_tmpdir();
 #else
 	const char *const_temp;
-	/* Try Unix env var. */
+	/* Unix doens't have a fancy function to get the standard
+	 * temporary directory an application can use. Instead there
+	 * is a convoluted set of possible paths that could be used.
+	 *
+	 * We're going to go though each one in a priority order and
+	 * verify if we can read and write the directory. If so then
+	 * that's the one that will be used. We are fine using access
+	 * here because it doesn't matter if the path ends up being
+	 * changed out from underneath us later on. When it's used
+	 * at that time it will fail. Right now we just want to get
+	 * a path that can be tried. */
+
+	/* Try Unix env vars.
+	 *
+	 * This is not ideal but a valid way to set the temporary directory
+	 * for a user. Per Single Unix Specification 4 and probably other things.
+	 */
 #  ifdef HAVE_SECURE_GETENV
 	const_temp = secure_getenv("TMPDIR");
 #  else
```
