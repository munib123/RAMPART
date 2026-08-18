# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 54-94 of the vulnerable file.

#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "c.h"
#include "fileutils.h"
#include "closestream.h"
#include "setpwnam.h"

static void pw_init(void);

/*
 *  setpwnam () --
 *	takes a struct passwd in which every field is filled in and valid.
 *	If the given username exists in the passwd file, the entry is
 *	replaced with the given entry.
 */
int setpwnam(struct passwd *pwd)
{
	FILE *fp = NULL, *pwf = NULL;
	int save_errno;
	int found;
	int namelen;
	int buflen = 256;
	int contlen, rc;
	char *linebuf = NULL;
	char *tmpname = NULL;
	char *atomic_dir = "/etc";

	pw_init();

	if ((fp = xfmkstemp(&tmpname, atomic_dir)) == NULL)
		return -1;

	/* ptmp should be owned by root.root or root.wheel */
	if (fchown(fileno(fp), (uid_t) 0, (gid_t) 0) < 0)
		goto fail;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
  *	If the given username exists in the passwd file, the entry is
  *	replaced with the given entry.
  */
-int setpwnam(struct passwd *pwd)
+int setpwnam(struct passwd *pwd, const char *prefix)
 {
 	FILE *fp = NULL, *pwf = NULL;
 	int save_errno;
@@ -81,11 +81,10 @@
 	int contlen, rc;
 	char *linebuf = NULL;
 	char *tmpname = NULL;
-	char *atomic_dir = "/etc";
 
 	pw_init();
 
-	if ((fp = xfmkstemp(&tmpname, atomic_dir)) == NULL)
+	if ((fp = xfmkstemp(&tmpname, "/etc", prefix)) == NULL)
 		return -1;
 
 	/* ptmp should be owned by root.root or root.wheel */
```
