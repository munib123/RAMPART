# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 867_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `867_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include "util.h"

#include <u2f-server.h>
#include <u2f-host.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>

#include <string.h>

int get_devices_from_authfile(const char *authfile, const char *username,
                              unsigned max_devs, int verbose, FILE *debug_file,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2014-2018 Yubico AB - See COPYING
+ * Copyright (C) 2014-2019 Yubico AB - See COPYING
  */
 
 #include "util.h"
@@ -36,7 +36,7 @@
   /* Ensure we never return uninitialized count. */
   *n_devs = 0;
 
-  fd = open(authfile, O_RDONLY, 0);
+  fd = open(authfile, O_RDONLY | O_CLOEXEC | O_NOCTTY);
   if (fd < 0) {
     if (verbose)
       D(debug_file, "Cannot open file: %s (%s)", authfile, strerror(errno));
@@ -83,6 +83,8 @@
     if (verbose)
       D(debug_file, "fdopen: %s", strerror(errno));
     goto err;
+  } else {
+    fd = -1; /* fd belongs to opwfile */
   }
 
   buf = malloc(sizeof(char) * (DEVSIZE * max_devs));
@@ -211,8 +213,10 @@
 
   if (opwfile)
     fclose(opwfile);
-  else if (fd >= 0)
+
+  if (fd != -1)
     close(fd);
+
   return retval;
 }
 
```
