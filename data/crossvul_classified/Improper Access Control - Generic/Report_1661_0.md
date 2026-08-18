# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-30 of the vulnerable file.

#ifndef UTIL_LINUX_FILEUTILS
#define UTIL_LINUX_FILEUTILS

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "c.h"

extern int xmkstemp(char **tmpname, char *dir);

static inline FILE *xfmkstemp(char **tmpname, char *dir)
{
	int fd;
	FILE *ret;

	fd = xmkstemp(tmpname, dir);
	if (fd == -1)
		return NULL;

	if (!(ret = fdopen(fd, "w+" UL_CLOEXECSTR))) {
		close(fd);
		return NULL;
	}
	return ret;
}

extern int dup_fd_cloexec(int oldfd, int lowfd);
extern int get_fd_tabsize(void);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,14 +7,14 @@
 
 #include "c.h"
 
-extern int xmkstemp(char **tmpname, char *dir);
+extern int xmkstemp(char **tmpname, const char *dir, const char *prefix);
 
-static inline FILE *xfmkstemp(char **tmpname, char *dir)
+static inline FILE *xfmkstemp(char **tmpname, const char *dir, const char *prefix)
 {
 	int fd;
 	FILE *ret;
 
-	fd = xmkstemp(tmpname, dir);
+	fd = xmkstemp(tmpname, dir, prefix);
 	if (fd == -1)
 		return NULL;
 
```
