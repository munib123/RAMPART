# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 867_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `867_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
 *  Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#include "util.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- *  Copyright (C) 2014-2018 Yubico AB - See COPYING
+ *  Copyright (C) 2014-2019 Yubico AB - See COPYING
  */
 
 /* Define which PAM interfaces we provide */
@@ -31,7 +31,11 @@
 #endif
 
 static void parse_cfg(int flags, int argc, const char **argv, cfg_t *cfg) {
+  struct stat st;
+  FILE *file = NULL;
+  int fd = -1;
   int i;
+
   memset(cfg, 0, sizeof(cfg_t));
   cfg->debug_file = stderr;
 
@@ -76,14 +80,14 @@
         cfg->debug_file = (FILE *)-1;
       }
       else {
-        struct stat st;
-        FILE *file;
-        if(lstat(filename, &st) == 0) {
-          if(S_ISREG(st.st_mode)) {
-            file = fopen(filename, "a");
-            if(file != NULL) {
-              cfg->debug_file = file;
-            }
+        fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
+        if (fd >= 0 && (fstat(fd, &st) == 0) && S_ISREG(st.st_mode)) {
+          file = fdopen(fd, "a");
+          if(file != NULL) {
+            cfg->debug_file = file;
+            cfg->is_custom_debug_file = 1;
+            file = NULL;
+            fd = -1;
           }
         }
       }
@@ -111,6 +115,12 @@
     D(cfg->debug_file, "appid=%s", cfg->appid ? cfg->appid : "(null)");
     D(cfg->debug_file, "prompt=%s", cfg->prompt ? cfg->prompt : "(null)");
   }
+
+  if (fd != -1)
+    close(fd);
+
+  if (file != NULL)
+    fclose(file);
 }
 
 #ifdef DBG
@@ -317,7 +327,8 @@
     DBG("Using file '%s' for emitting touch request notifications", cfg->authpending_file);
 
     // Open (or create) the authpending_file to indicate that we start waiting for a touch
-    authpending_file_descriptor = open(cfg->authpending_file, O_RDONLY | O_CREAT, 0664);
+    authpending_file_descriptor =
+      open(cfg->authpending_file, O_RDONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY, 0664);
     if (authpending_file_descriptor < 0) {
       DBG("Unable to emit 'authentication started' notification by opening the file '%s', (%s)",
           cfg->authpending_file, strerror(errno));
@@ -384,6 +395,10 @@
     retval = PAM_SUCCESS;
   }
   DBG("done. [%s]", pam_strerror(pamh, retval));
+
+  if (cfg->is_custom_debug_file) {
+    fclose(cfg->debug_file);
+  }
 
   return retval;
 }
```
