# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3151_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3151_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 23-63 of the vulnerable file.

#include <glob.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>

static void skel(const char *homedir, uid_t u, gid_t g) {
	char *fname;
	// zsh
	if (arg_zsh) {
		// copy skel files
		if (asprintf(&fname, "%s/.zshrc", homedir) == -1)
			errExit("asprintf");
		struct stat s;
		// don't copy it if we already have the file
		if (stat(fname, &s) == 0)
			return;
		if (stat("/etc/skel/.zshrc", &s) == 0) {
			if (is_link("/etc/skel/.zshrc")) {
				fprintf(stderr, "Error: invalid /etc/skel/.zshrc file\n");
				exit(1);
			}
			if (copy_file("/etc/skel/.zshrc", fname) == 0) {
				if (chown(fname, u, g) == -1)
					errExit("chown");
				fs_logger("clone /etc/skel/.zshrc");
			}
		}
		else { // 
			FILE *fp = fopen(fname, "w");
			if (fp) {
				fprintf(fp, "\n");
				fclose(fp);
				if (chown(fname, u, g) == -1)
					errExit("chown");
				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
					errExit("chown");
				fs_logger2("touch", fname);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,28 +40,17 @@
 		// don't copy it if we already have the file
 		if (stat(fname, &s) == 0)
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.zshrc", &s) == 0) {
-			if (is_link("/etc/skel/.zshrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.zshrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.zshrc", fname) == 0) {
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.zshrc");
-			}
-		}
-		else { // 
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
-			}
+			copy_file_as_user("/etc/skel/.zshrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.zshrc");
+		}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
 		}
 		free(fname);
 	}
@@ -74,29 +63,17 @@
 		// don't copy it if we already have the file
 		if (stat(fname, &s) == 0)
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.cshrc", &s) == 0) {
-			if (is_link("/etc/skel/.cshrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.cshrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.cshrc", fname) == 0) {
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.cshrc");
-			}
-		}
-		else { // 
-			/* coverity[toctou] */
-			FILE *fp = fopen(fname, "w");
-			if (fp) {
-				fprintf(fp, "\n");
-				fclose(fp);
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				if (chmod(fname, S_IRUSR | S_IWUSR) < 0)
-					errExit("chown");
-				fs_logger2("touch", fname);
-			}
+			copy_file_as_user("/etc/skel/.cshrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.cshrc");
+		}
+		else {
+			touch_file_as_user(fname, u, g, 0644);
+			fs_logger2("touch", fname);
 		}
 		free(fname);
 	}
@@ -107,19 +84,15 @@
 			errExit("asprintf");
 		struct stat s;
 		// don't copy it if we already have the file
-		if (stat(fname, &s) == 0)
+		if (stat(fname, &s) == 0) 
 			return;
+		if (is_link(fname)) { // stat on dangling symlinks fails, try again using lstat
+			fprintf(stderr, "Error: invalid %s file\n", fname);
+			exit(1);
+		}
 		if (stat("/etc/skel/.bashrc", &s) == 0) {
-			if (is_link("/etc/skel/.bashrc")) {
-				fprintf(stderr, "Error: invalid /etc/skel/.bashrc file\n");
-				exit(1);
-			}
-			if (copy_file("/etc/skel/.bashrc", fname) == 0) {
-				/* coverity[toctou] */
-				if (chown(fname, u, g) == -1)
-					errExit("chown");
-				fs_logger("clone /etc/skel/.bashrc");
-			}
+			copy_file_as_user("/etc/skel/.bashrc", fname, u, g, 0644); // regular user
+			fs_logger("clone /etc/skel/.bashrc");
 		}
 		free(fname);
 	}
@@ -131,48 +104,26 @@
 
 	char *src;
 	char *dest = RUN_XAUTHORITY_FILE;
-	// create an empty file 
+	// create an empty file as root, and change ownership to user
 	FILE *fp = fopen(dest, "w");
 	if (fp) {
 		fprintf(fp, "\n");
 		SET_PERMS_STREAM(fp, getuid(), getgid(), 0600);
 		fclose(fp);
 	}
-
+	
 	if (asprintf(&src, "%s/.Xauthority", cfg.homedir) == -1)
 		errExit("asprintf");
 	
 	struct stat s;
 	if (stat(src, &s) == 0) {
 		if (is_link(src)) {
-			fprintf(stderr, "Error: invalid .Xauthority file\n");
-			exit(1);
-		}
-			
-		pid_t child = fork();
-		if (child < 0)
-			errExit("fork");
-		if (child == 0) {
-			// drop privileges
-			drop_privs(0);
-	
-			// copy, set permissions and ownership
-			int rv = copy_file(src, dest);
-			if (rv)
-				fprintf(stderr, "Warning: cannot transfer .Xauthority in private home directory\n");
-			else {
-				fs_logger2("clone", dest);
-			}
-				
-			_exit(0);
-		}
-		// wait for the child to finish
-		waitpid(child, NULL, 0);
-
-		if (chown(dest, getuid(), getgid()) == -1)
-			errExit("fchown");
-		if (chmod(dest, 0600) == -1)
-			errExit("fchmod");
+			fprintf(stderr, "Warning: invalid .Xauthority file\n");
+			return 0;
+		}
+
+		copy_file_as_user(src, dest, getuid(), getgid(), 0600); // regular user
+		fs_logger2("clone", dest);
 		return 1; // file copied
 	}
 	
@@ -185,47 +136,36 @@
 
 	char *src;
 	char *dest = RUN_ASOUNDRC_FILE;
-	// create an empty file 
+	// create an empty file as root, and change ownership to user
 	FILE *fp = fopen(dest, "w");
 	if (fp) {
 		fprintf(fp, "\n");
 		SET_PERMS_STREAM(fp, getuid(), getgid(), 0644);
 		fclose(fp);
 	}
-
+	
 	if (asprintf(&src, "%s/.asoundrc", cfg.homedir) == -1)
 		errExit("asprintf");
 	
 	struct stat s;
-	if (stat(src, &s) == 0) {	
+	if (stat(src, &s) == 0) {
 		if (is_link(src)) {
-			fprintf(stderr, "Error: invalid .asoundrc file\n");
-			exit(1);
-		}
-
-		pid_t child = fork();
-		if (child < 0)
-			errExit("fork");
-		if (child == 0) {
-			// drop privileges
-			drop_privs(0);
-	
-			// copy, set permissions and ownership
-			int rv = copy_file(src, dest);
-			if (rv)
-				fprintf(stderr, "Warning: cannot transfer .asoundrc in private home directory\n");
-			else {
-				fs_logger2("clone", dest);
+			// make sure the real path of the file is inside the home directory
+			/* coverity[toctou] */
+			char* rp = realpath(src, NULL);
+			if (!rp) {
+				fprintf(stderr, "Error: Cannot access %s\n", src);
+				exit(1);
 			}
-			_exit(0);
-		}
-		// wait for the child to finish
-		waitpid(child, NULL, 0);
-
-		if (chown(dest, getuid(), getgid()) == -1)
-			errExit("fchown");
-		if (chmod(dest, 0644) == -1)
-			errExit("fchmod");
+			if (strncmp(rp, cfg.homedir, strlen(cfg.homedir)) != 0) {
+				fprintf(stderr, "Error: .asoundrc is a symbolic link pointing to a file outside home directory\n");
+				exit(1);
+			}
+			free(rp);
+		}
+
+		copy_file_as_user(src, dest, getuid(), getgid(), 0644); // regular user
+		fs_logger2("clone", dest);
 		return 1; // file copied
 	}
 	
@@ -238,38 +178,16 @@
 	char *dest;
 	if (asprintf(&dest, "%s/.Xauthority", cfg.homedir) == -1)
 		errExit("asprintf");
-
+	
 	// if destination is a symbolic link, exit the sandbox!!!
 	if (is_link(dest)) {
 		fprintf(stderr, "Error: %s is a symbolic link\n", dest);
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
-		int rv = copy_file(src, dest);
-		if (rv)
-			fprintf(stderr, "Warning: cannot transfer .Xauthority in private home directory\n");
-		else {
-			fs_logger2("clone", dest);
-		}
-		_exit(0);
-	}
-	// wait for the child to finish
-	waitpid(child, NULL, 0);
-
-	// set permissions and ownership
-	if (chown(dest, getuid(), getgid()) < 0)
-		errExit("chown");
-	if (chmod(dest, S_IRUSR | S_IWUSR) < 0)
-		errExit("chmod");
-
+	copy_file_as_user(src, dest, getuid(), getgid(), S_IRUSR | S_IWUSR); // regular user
+	fs_logger2("clone", dest);
+	
 	// delete the temporary file
 	unlink(src);
 }
@@ -280,37 +198,15 @@
 	char *dest;
 	if (asprintf(&dest, "%s/.asoundrc", cfg.homedir) == -1)
 		errExit("asprintf");
-
+	
 	// if destination is a symbolic link, exit the sandbox!!!
 	if (is_link(dest)) {
 		fprintf(stderr, "Error: %s is a symbolic link\n", dest);
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
-		int rv = copy_file(src, dest);
-		if (rv)
-			fprintf(stderr, "Warning: cannot transfer .asoundrc in private home directory\n");
-		else {
-			fs_logger2("clone", dest);
-		}
-		_exit(0);
-	}
-	// wait for the child to finish
-	waitpid(child, NULL, 0);
-
-	// set permissions and ownership
-	if (chown(dest, getuid(), getgid()) < 0)
-		errExit("chown");
... (diff truncated)
```
