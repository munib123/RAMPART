# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3152_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3152_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 26-68 of the vulnerable file.

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
			if (copy_file("/etc/skel/.zshrc", fname, u, g, 0644) == 0) {
				fs_logger("clone /etc/skel/.zshrc");
			}
		}
		else { // 
			FILE *fp = fopen(fname, "w");
			if (fp) {
				fprintf(fp, "\n");
				SET_PERMS_STREAM(fp, u, g, S_IRUSR | S_IWUSR);
				fclose(fp);
				fs_logger2("touch", fname);
			}
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,18 +43,12 @@
 		if (stat(fname, &s) == 0)
 			return;
 		if (stat("/etc/skel/.zshrc", &s) == 0) {
-			if (copy_file("/etc/skel/.zshrc", fname, u, g, 0644) == 0) {
-				fs_logger("clone /etc/skel/.zshrc");
-			}
-		}
-		else { // 
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				SET_PERMS_STREAM(fp, u, g, S_IRUSR | S_IWUSR);
-				fclose(fp);
-				fs_logger2("touch", fname);
-			}
+			copy_file("/etc/skel/.zshrc", fname, u, g, 0644);
+			fs_logger("clone /etc/skel/.zshrc");
+		}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
 		}
 		free(fname);
 	}
@@ -68,19 +62,12 @@
 		if (stat(fname, &s) == 0)
 			return;
 		if (stat("/etc/skel/.cshrc", &s) == 0) {
-			if (copy_file("/etc/skel/.cshrc", fname, u, g, 0644) == 0) {
-				fs_logger("clone /etc/skel/.cshrc");
-			}
-		}
-		else { // 
-			/* coverity[toctou] */
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				SET_PERMS_STREAM(fp, u, g, S_IRUSR | S_IWUSR);
-				fclose(fp);
-				fs_logger2("touch", fname);
-			}
+			copy_file("/etc/skel/.cshrc", fname, u, g, 0644);
+			fs_logger("clone /etc/skel/.cshrc");
+		}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
 		}
 		free(fname);
 	}
@@ -94,9 +81,8 @@
 		if (stat(fname, &s) == 0) 
 			return;
 		if (stat("/etc/skel/.bashrc", &s) == 0) {
-			if (copy_file("/etc/skel/.bashrc", fname, u, g, 0644) == 0) {
-				fs_logger("clone /etc/skel/.bashrc");
-			}
+			copy_file("/etc/skel/.bashrc", fname, u, g, 0644);
+			fs_logger("clone /etc/skel/.bashrc");
 		}
 		free(fname);
 	}
@@ -126,24 +112,8 @@
 			return 0;
 		}
 
-		pid_t child = fork();
-		if (child < 0)
-			errExit("fork");
-		if (child == 0) {
-			// drop privileges
-			drop_privs(0);
-	
-			// copy, set permissions and ownership
-			int rv = copy_file(src, dest, getuid(), getgid(), 0600);
-			if (rv)
-				fprintf(stderr, "Warning: cannot transfer .Xauthority in private home directory\n");
-			else {
-				fs_logger2("clone", dest);
-			}
-			_exit(0);
-		}
-		// wait for the child to finish
-		waitpid(child, NULL, 0);
+		copy_file_as_user(src, dest, getuid(), getgid(), 0600);
+		fs_logger2("clone", dest);
 		return 1; // file copied
 	}
 	
@@ -184,24 +154,8 @@
 			free(rp);
 		}
 
-		pid_t child = fork();
-		if (child < 0)
-			errExit("fork");
-		if (child == 0) {
-			// drop privileges
-			drop_privs(0);
-	
-			// copy, set permissions and ownership
-			int rv = copy_file(src, dest, getuid(), getgid(), 0644);
-			if (rv)
-				fprintf(stderr, "Warning: cannot transfer .asoundrc in private home directory\n");
-			else {
-				fs_logger2("clone", dest);
-			}
-			_exit(0);
-		}
-		// wait for the child to finish
-		waitpid(child, NULL, 0);
+		copy_file_as_user(src, dest, getuid(), getgid(), 0644);
+		fs_logger2("clone", dest);
 		return 1; // file copied
 	}
 	
@@ -221,24 +175,8 @@
 		exit(1);
 	}
 
-	pid_t child = fork();
-	if (child < 0)
-		errExit("fork");
-	if (child == 0) {
-		// drop privileges
-		drop_privs(0);
-
-		// copy, set permissions and ownership
-		int rv = copy_file(src, dest, getuid(), getgid(), S_IRUSR | S_IWUSR);
-		if (rv)
-			fprintf(stderr, "Warning: cannot transfer .Xauthority in private home directory\n");
-		else {
-			fs_logger2("clone", dest);
-		}
-		_exit(0);
-	}
-	// wait for the child to finish
-	waitpid(child, NULL, 0);
+	copy_file_as_user(src, dest, getuid(), getgid(), S_IRUSR | S_IWUSR);
+	fs_logger2("clone", dest);
 	
 	// delete the temporary file
 	unlink(src);
@@ -257,24 +195,8 @@
 		exit(1);
 	}
 
-	pid_t child = fork();
-	if (child < 0)
-		errExit("fork");
-	if (child == 0) {
-		// drop privileges
-		drop_privs(0);
-
-		// copy, set permissions and ownership
-		int rv = copy_file(src, dest, getuid(), getgid(), S_IRUSR | S_IWUSR);
-		if (rv)
-			fprintf(stderr, "Warning: cannot transfer .asoundrc in private home directory\n");
-		else {
-			fs_logger2("clone", dest);
-		}
-		_exit(0);
-	}
-	// wait for the child to finish
-	waitpid(child, NULL, 0);
+	copy_file_as_user(src, dest, getuid(), getgid(), S_IRUSR | S_IWUSR);
+	fs_logger2("clone", dest);
 
 	// delete the temporary file
 	unlink(src);
```
