# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-38 of the vulnerable file.

/*
 * Copyright (C) 2012 Sami Kerola <kerolasa@iki.fi>
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "c.h"
#include "fileutils.h"
#include "pathnames.h"

/* Create open temporary file in safe way.  Please notice that the
 * file permissions are -rw------- by default. */
int xmkstemp(char **tmpname, char *dir)
{
	char *localtmp;
	char *tmpenv;
	mode_t old_mode;
	int fd, rc;

	/* Some use cases must be capable of being moved atomically
	 * with rename(2), which is the reason why dir is here.  */
	if (dir != NULL)
		tmpenv = dir;
	else
		tmpenv = getenv("TMPDIR");

	if (tmpenv)
		rc = asprintf(&localtmp, "%s/%s.XXXXXX", tmpenv,
			  program_invocation_short_name);
	else
		rc = asprintf(&localtmp, "%s/%s.XXXXXX", _PATH_TMP,
			  program_invocation_short_name);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,27 +15,20 @@
 
 /* Create open temporary file in safe way.  Please notice that the
  * file permissions are -rw------- by default. */
-int xmkstemp(char **tmpname, char *dir)
+int xmkstemp(char **tmpname, const char *dir, const char *prefix)
 {
 	char *localtmp;
-	char *tmpenv;
+	const char *tmpenv;
 	mode_t old_mode;
 	int fd, rc;
 
 	/* Some use cases must be capable of being moved atomically
 	 * with rename(2), which is the reason why dir is here.  */
-	if (dir != NULL)
-		tmpenv = dir;
-	else
-		tmpenv = getenv("TMPDIR");
+	tmpenv = dir ? dir : getenv("TMPDIR");
+	if (!tmpenv)
+		tmpenv = _PATH_TMP;
 
-	if (tmpenv)
-		rc = asprintf(&localtmp, "%s/%s.XXXXXX", tmpenv,
-			  program_invocation_short_name);
-	else
-		rc = asprintf(&localtmp, "%s/%s.XXXXXX", _PATH_TMP,
-			  program_invocation_short_name);
-
+	rc = asprintf(&localtmp, "%s/%s.XXXXXX", tmpenv, prefix);
 	if (rc < 0)
 		return -1;
 
@@ -107,7 +100,7 @@
 {
 	FILE *f;
 	char *tmpname;
-	f = xfmkstemp(&tmpname, NULL);
+	f = xfmkstemp(&tmpname, NULL, "test");
 	unlink(tmpname);
 	free(tmpname);
 	fclose(f);
```
