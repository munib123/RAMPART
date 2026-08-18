# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 4261_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4261_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 75-115 of the vulnerable file.

	} else {
		/*
		 * Check realpath() of directory containing the file, a
		 * STOR may want to save a new file.  Then append the
		 * file and return it.
		 */
		name = basename(path);
		ptr = dirname(dir);

		memset(rpath, 0, sizeof(rpath));
		if (!realpath(ptr, rpath)) {
			INFO("Failed realpath(%s): %m", ptr);
			return NULL;
		}

		if (rpath[1] != 0)
			strlcat(rpath, "/", sizeof(rpath));
		strlcat(rpath, name, sizeof(rpath));
	}

	if (!chrooted && strncmp(dir, home, strlen(home))) {
		DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
		return NULL;
	}

	return rpath;
}

char *compose_abspath(ctrl_t *ctrl, char *path)
{
	char *ptr;
	char cwd[sizeof(ctrl->cwd)];

	if (path && path[0] == '/') {
		strlcpy(cwd, ctrl->cwd, sizeof(cwd));
		memset(ctrl->cwd, 0, sizeof(ctrl->cwd));
	}

	ptr = compose_path(ctrl, path);

	if (path && path[0] == '/')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,7 +92,7 @@
 		strlcat(rpath, name, sizeof(rpath));
 	}
 
-	if (!chrooted && strncmp(dir, home, strlen(home))) {
+	if (!chrooted && strncmp(rpath, home, strlen(home))) {
 		DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
 		return NULL;
 	}
```
