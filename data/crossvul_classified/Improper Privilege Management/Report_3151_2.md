# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3151_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3151_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 195-235 of the vulnerable file.

	static const int BUFLEN = 1024;
	unsigned char buf[BUFLEN];
	while ((len = read(src, buf, BUFLEN)) > 0) {
		int done = 0;
		while (done != len) {
			int rv = write(dst, buf + done, len - done);
			if (rv == -1) {
				close(src);
				close(dst);
				return -1;
			}

			done += rv;
		}
	}

	close(src);
	close(dst);
	return 0;
}

// return 1 if the file is a directory
int is_dir(const char *fname) {
	assert(fname);
	if (*fname == '\0')
		return 0;
	
	// if fname doesn't end in '/', add one
	int rv;
	struct stat s;
	if (fname[strlen(fname) - 1] == '/')
		rv = stat(fname, &s);
	else {
		char *tmp;
		if (asprintf(&tmp, "%s/", fname) == -1) {
			fprintf(stderr, "Error: cannot allocate memory, %s:%d\n", __FILE__, __LINE__);
			errExit("asprintf");
		}		
		rv = stat(tmp, &s);
		free(tmp);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,6 +213,53 @@
 	return 0;
 }
 
+// return -1 if error, 0 if no error
+void copy_file_as_user(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode) {
+	pid_t child = fork();
+	if (child < 0)
+		errExit("fork");
+	if (child == 0) {
+		// drop privileges
+		drop_privs(0);
+
+		// copy, set permissions and ownership
+		int rv = copy_file(srcname, destname); // already a regular user
+		if (rv)
+			fprintf(stderr, "Warning: cannot copy %s\n", srcname);
+		else {
+			if (chown(destname, uid, gid) == -1)
+				errExit("fchown");
+			if (chmod(destname, mode) == -1)
+				errExit("fchmod");
+		}
+		_exit(0);
+	}
+	// wait for the child to finish
+	waitpid(child, NULL, 0);
+}
+
+// return -1 if error, 0 if no error
+void touch_file_as_user(const char *fname, uid_t uid, gid_t gid, mode_t mode) {
+	pid_t child = fork();
+	if (child < 0)
+		errExit("fork");
+	if (child == 0) {
+		// drop privileges
+		drop_privs(0);
+
+		FILE *fp = fopen(fname, "w");
+		if (fp) {
+			fprintf(fp, "\n");
+			SET_PERMS_STREAM(fp, uid, gid, mode);
+			fclose(fp);
+		}
+		_exit(0);
+	}
+	// wait for the child to finish
+	waitpid(child, NULL, 0);
+}
+
+
 // return 1 if the file is a directory
 int is_dir(const char *fname) {
 	assert(fname);
```
