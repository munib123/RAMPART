# CrossVul Fix Pair: Untrusted Search Path in c
**Pair ID:** 1608_1
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1608_1`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```c
Lines 16-56 of the vulnerable file.

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "common.h"

static int usage(char **argv) {
	printf("\nUsage:\t%s -q -f config_file program_name [arguments]\n"
	       "\t-q makes proxychains quiet - this overrides the config setting\n"
	       "\t-f allows to manually specify a configfile to use\n"
	       "\tfor example : proxychains telnet somehost.com\n" "More help in README file\n\n", argv[0]);
	return EXIT_FAILURE;
}

static const char *dll_name = DLL_NAME;

static char own_dir[256];
static const char *dll_dirs[] = {
	".",
	own_dir,
	LIB_DIR,
	"/lib",
	"/usr/lib",
	"/usr/local/lib",
	"/lib64",
	NULL
};

static void set_own_dir(const char *argv0) {
	size_t l = strlen(argv0);
	while(l && argv0[l - 1] != '/')
		l--;
	if(l == 0)
		memcpy(own_dir, ".", 2);
	else {
		memcpy(own_dir, argv0, l - 1);
		own_dir[l] = 0;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,9 @@
 
 static char own_dir[256];
 static const char *dll_dirs[] = {
+#ifndef SUPER_SECURE /* CVE-2015-3887 */
 	".",
+#endif
 	own_dir,
 	LIB_DIR,
 	"/lib",
@@ -48,7 +50,11 @@
 	while(l && argv0[l - 1] != '/')
 		l--;
 	if(l == 0)
+#ifdef SUPER_SECURE
+		memcpy(own_dir, "/dev/null/", 2);
+#else
 		memcpy(own_dir, ".", 2);
+#endif
 	else {
 		memcpy(own_dir, argv0, l - 1);
 		own_dir[l] = 0;
```
