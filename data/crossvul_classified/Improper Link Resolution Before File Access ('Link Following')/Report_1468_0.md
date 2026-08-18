# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1468_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1468_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.


static void unlock_mutex(pthread_mutex_t *l)
{
	int ret;

	if ((ret = pthread_mutex_unlock(l)) != 0) {
		fprintf(stderr, "pthread_mutex_unlock returned:%d %s\n", ret, strerror(ret));
		dump_stacktrace();
		exit(1);
	}
}

static char *lxclock_name(const char *p, const char *n)
{
	int ret;
	int len;
	char *dest;
	char *rundir;

	/* lockfile will be:
	 * "/run" + "/lock/lxc/$lxcpath/$lxcname + '\0' if root
	 * or
	 * $XDG_RUNTIME_DIR + "/lock/lxc/$lxcpath/$lxcname + '\0' if non-root
	 */

	/* length of "/lock/lxc/" + $lxcpath + "/" + "." + $lxcname + '\0' */
	len = strlen("/lock/lxc/") + strlen(n) + strlen(p) + 3;
	rundir = get_rundir();
	if (!rundir)
		return NULL;
	len += strlen(rundir);

	if ((dest = malloc(len)) == NULL) {
		free(rundir);
		return NULL;
	}

	ret = snprintf(dest, len, "%s/lock/lxc/%s", rundir, p);
	if (ret < 0 || ret >= len) {
		free(dest);
		free(rundir);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,13 +103,13 @@
 	char *rundir;
 
 	/* lockfile will be:
-	 * "/run" + "/lock/lxc/$lxcpath/$lxcname + '\0' if root
+	 * "/run" + "/lxc/lock/$lxcpath/$lxcname + '\0' if root
 	 * or
-	 * $XDG_RUNTIME_DIR + "/lock/lxc/$lxcpath/$lxcname + '\0' if non-root
+	 * $XDG_RUNTIME_DIR + "/lxc/lock/$lxcpath/$lxcname + '\0' if non-root
 	 */
 
-	/* length of "/lock/lxc/" + $lxcpath + "/" + "." + $lxcname + '\0' */
-	len = strlen("/lock/lxc/") + strlen(n) + strlen(p) + 3;
+	/* length of "/lxc/lock/" + $lxcpath + "/" + "." + $lxcname + '\0' */
+	len = strlen("/lxc/lock/") + strlen(n) + strlen(p) + 3;
 	rundir = get_rundir();
 	if (!rundir)
 		return NULL;
@@ -120,7 +120,7 @@
 		return NULL;
 	}
 
-	ret = snprintf(dest, len, "%s/lock/lxc/%s", rundir, p);
+	ret = snprintf(dest, len, "%s/lxc/lock/%s", rundir, p);
 	if (ret < 0 || ret >= len) {
 		free(dest);
 		free(rundir);
@@ -128,40 +128,13 @@
 	}
 	ret = mkdir_p(dest, 0755);
 	if (ret < 0) {
-		/* fall back to "/tmp/" + $(id -u) + "/lxc" + $lxcpath + "/" + "." + $lxcname + '\0'
-		 * * maximum length of $(id -u) is 10 calculated by (log (2 ** (sizeof(uid_t) * 8) - 1) / log 10 + 1)
-		 * * lxcpath always starts with '/'
-		 */
-		int l2 = 22 + strlen(n) + strlen(p);
-		if (l2 > len) {
-			char *d;
-			d = realloc(dest, l2);
-			if (!d) {
-				free(dest);
-				free(rundir);
-				return NULL;
-			}
-			len = l2;
-			dest = d;
-		}
-		ret = snprintf(dest, len, "/tmp/%d/lxc%s", geteuid(), p);
-		if (ret < 0 || ret >= len) {
-			free(dest);
-			free(rundir);
-			return NULL;
-		}
-		ret = mkdir_p(dest, 0755);
-		if (ret < 0) {
-			free(dest);
-			free(rundir);
-			return NULL;
-		}
-		ret = snprintf(dest, len, "/tmp/%d/lxc%s/.%s", geteuid(), p, n);
-	} else
-		ret = snprintf(dest, len, "%s/lock/lxc/%s/.%s", rundir, p, n);
-
+		free(dest);
+		free(rundir);
+		return NULL;
+	}
+
+	ret = snprintf(dest, len, "%s/lxc/lock/%s/.%s", rundir, p, n);
 	free(rundir);
-
 	if (ret < 0 || ret >= len) {
 		free(dest);
 		return NULL;
```
