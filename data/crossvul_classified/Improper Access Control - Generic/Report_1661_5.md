# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-29 of the vulnerable file.

/*
 *  setpwnam.h --
 *  define several paths
 *
 *  (c) 1994 Martin Schulze <joey@infodrom.north.de>
 *  This file is based on setpwnam.c which is
 *  (c) 1994 Salvatore Valente <svalente@mit.edu>
 *
 *  This file is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 */

#include "pathnames.h"

#ifndef DEBUG
# define PASSWD_FILE	_PATH_PASSWD
# define GROUP_FILE	_PATH_GROUP
# define SHADOW_FILE	_PATH_SHADOW_PASSWD
# define SGROUP_FILE	_PATH_GSHADOW
#else
# define PASSWD_FILE	"/tmp/passwd"
# define GROUP_FILE	"/tmp/group"
# define SHADOW_FILE	"/tmp/shadow"
# define SGROUP_FILE	"/tmp/gshadow"
#endif

extern int setpwnam (struct passwd *pwd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,8 @@
  *  published by the Free Software Foundation; either version 2 of the
  *  License, or (at your option) any later version.
  */
+#ifndef UTIL_LINUX_SETPWNAM_H
+#define UTIL_LINUX_SETPWNAM_H
 
 #include "pathnames.h"
 
@@ -26,4 +28,6 @@
 # define SGROUP_FILE	"/tmp/gshadow"
 #endif
 
-extern int setpwnam (struct passwd *pwd);
+extern int setpwnam (struct passwd *pwd, const char *prefix);
+
+#endif /* UTIL_LINUX_SETPWNAM_H */
```
