# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3150_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3150_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <ftw.h>

static void skel(const char *homedir, uid_t u, gid_t g) {
	char *fname;

	// zsh
	if (!arg_shell_none && (strcmp(cfg.shell,"/usr/bin/zsh") == 0 || strcmp(cfg.shell,"/bin/zsh") == 0)) {
		// copy skel files
		if (asprintf(&fname, "%s/.zshrc", homedir) == -1)
			errExit("asprintf");
		struct stat s;
		// don't copy it if we already have the file
		if (stat(fname, &s) == 0)
			return;
		if (stat("/etc/skel/.zshrc", &s) == 0) {
			copy_file("/etc/skel/.zshrc", fname, u, g, 0644);
			fs_logger("clone /etc/skel/.zshrc");
		}
		else {
			touch_file_as_user(fname, u, g, 0644);
			fs_logger2("touch", fname);
		}
		free(fname);
	}
	// csh
	else if (!arg_shell_none && strcmp(cfg.shell,"/bin/csh") == 0) {
		// copy skel files
		if (asprintf(&fname, "%s/.cshrc", homedir) == -1)
			errExit("asprintf");
		struct stat s;
		// don't copy it if we already have the file
		if (stat(fname, &s) == 0)
			return;
		if (stat("/etc/skel/.cshrc", &s) == 0) {
			copy_file("/etc/skel/.cshrc", fname, u, g, 0644);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,8 +42,12 @@
 		// don't copy it if we already have the file
 		if (stat(fname, &s) == 0)
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.zshrc", &s) == 0) {
-			copy_file("/etc/skel/.zshrc", fname, u, g, 0644);
+			copy_file_as_user("/etc/skel/.zshrc", fname, u, g, 0644);
 			fs_logger("clone /etc/skel/.zshrc");
 		}
 		else {
@@ -61,8 +65,12 @@
 		// don't copy it if we already have the file
 		if (stat(fname, &s) == 0)
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.cshrc", &s) == 0) {
-			copy_file("/etc/skel/.cshrc", fname, u, g, 0644);
+			copy_file_as_user("/etc/skel/.cshrc", fname, u, g, 0644);
 			fs_logger("clone /etc/skel/.cshrc");
 		}
 		else {
@@ -80,8 +88,12 @@
 		// don't copy it if we already have the file
 		if (stat(fname, &s) == 0) 
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.bashrc", &s) == 0) {
-			copy_file("/etc/skel/.bashrc", fname, u, g, 0644);
+			copy_file_as_user("/etc/skel/.bashrc", fname, u, g, 0644);
 			fs_logger("clone /etc/skel/.bashrc");
 		}
 		free(fname);
@@ -94,7 +106,7 @@
 
 	char *src;
 	char *dest = RUN_XAUTHORITY_FILE;
-	// create an empty file 
+	// create an empty file as root, and change ownership to user
 	FILE *fp = fopen(dest, "w");
 	if (fp) {
 		fprintf(fp, "\n");
@@ -126,7 +138,7 @@
 
 	char *src;
 	char *dest = RUN_ASOUNDRC_FILE;
-	// create an empty file 
+	// create an empty file as root, and change ownership to user
 	FILE *fp = fopen(dest, "w");
 	if (fp) {
 		fprintf(fp, "\n");
```
