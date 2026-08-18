# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 880_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `880_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 116-156 of the vulnerable file.


	// run fldd to extract the list of files
	if (arg_debug || arg_debug_private_lib)
		printf("    running fldd %s\n", full_path);
	sbox_run(SBOX_USER | SBOX_SECCOMP | SBOX_CAPS_NONE, 3, PATH_FLDD, full_path, RUN_LIB_FILE);

	// open the list of libraries and install them on by one
	FILE *fp = fopen(RUN_LIB_FILE, "r");
	if (!fp)
		errExit("fopen");

	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp)) {
		// remove \n
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		fslib_duplicate(buf);
	}
	fclose(fp);
}


void fslib_copy_dir(const char *full_path) {
	assert(full_path);
	if (arg_debug || arg_debug_private_lib)
		printf("    fslib_copy_dir %s\n", full_path);

	// do nothing if the directory does not exist or is not owned by root
	struct stat s;
	if (stat(full_path, &s) != 0 || s.st_uid != 0 || !S_ISDIR(s.st_mode) || access(full_path, R_OK))
		return;

	char *dir_name = strrchr(full_path, '/');
	assert(dir_name);
	dir_name++;
	assert(*dir_name != '\0');

	// do nothing if the directory is already there
	char *dest;
	if (asprintf(&dest, "%s/%s", build_dest_dir(full_path), dir_name) == -1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,6 +133,7 @@
 		fslib_duplicate(buf);
 	}
 	fclose(fp);
+	unlink(RUN_LIB_FILE);
 }
 
 
```
