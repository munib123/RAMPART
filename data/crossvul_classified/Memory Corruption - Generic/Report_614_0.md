# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 614_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `614_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3657-3699 of the vulnerable file.

		return -1;
	}
	return 0;
}

void uwsgi_write_pidfile(char *pidfile_name) {
	uwsgi_log("writing pidfile to %s\n", pidfile_name);
	if (uwsgi_write_intfile(pidfile_name, (int) getpid())) {
		uwsgi_log("could not write pidfile.\n");
	}
}

void uwsgi_write_pidfile_explicit(char *pidfile_name, pid_t pid) {
	uwsgi_log("writing pidfile to %s\n", pidfile_name);
	if (uwsgi_write_intfile(pidfile_name, (int) pid)) {
		uwsgi_log("could not write pidfile.\n");
	}
}

char *uwsgi_expand_path(char *dir, int dir_len, char *ptr) {
	char src[PATH_MAX + 1];
	memcpy(src, dir, dir_len);
	src[dir_len] = 0;
	char *dst = ptr;
	if (!dst)
		dst = uwsgi_malloc(PATH_MAX + 1);
	if (!realpath(src, dst)) {
		uwsgi_error_realpath(src);
		if (!ptr)
			free(dst);
		return NULL;
	}
	return dst;
}


void uwsgi_set_cpu_affinity() {
	char buf[4096];
	int ret;
	int pos = 0;
	if (uwsgi.cpu_affinity) {
		int base_cpu = (uwsgi.mywid - 1) * uwsgi.cpu_affinity;
		if (base_cpu >= uwsgi.cpus) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3674,9 +3674,12 @@
 }
 
 char *uwsgi_expand_path(char *dir, int dir_len, char *ptr) {
-	char src[PATH_MAX + 1];
-	memcpy(src, dir, dir_len);
-	src[dir_len] = 0;
+	if (dir_len > PATH_MAX)
+	{
+		uwsgi_log("invalid path size: %d (max %d)\n", dir_len, PATH_MAX);
+		return NULL;
+	}
+	char *src = uwsgi_concat2n(dir, dir_len, "", 0);
 	char *dst = ptr;
 	if (!dst)
 		dst = uwsgi_malloc(PATH_MAX + 1);
@@ -3684,8 +3687,10 @@
 		uwsgi_error_realpath(src);
 		if (!ptr)
 			free(dst);
+		free(src);
 		return NULL;
 	}
+	free(src);
 	return dst;
 }
 
```
