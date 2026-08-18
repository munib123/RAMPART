# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 866_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `866_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 3-43 of the vulnerable file.

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

/* If secure_getenv is not defined, define it here */
#ifndef HAVE_SECURE_GETENV
char *secure_getenv(const char *);
char *secure_getenv(const char *name) {
  (void)name;
  return NULL;
}
#endif

static void parse_cfg(int flags, int argc, const char **argv, cfg_t *cfg) {
  struct stat st;
  FILE *file = NULL;
  int fd = -1;
  int i;

  memset(cfg, 0, sizeof(cfg_t));
  cfg->debug_file = stderr;

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "max_devices=", 12) == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 #include <errno.h>
 
 #include "util.h"
+#include "drop_privs.h"
 
 /* If secure_getenv is not defined, define it here */
 #ifndef HAVE_SECURE_GETENV
@@ -148,11 +149,12 @@
   int retval = PAM_IGNORE;
   device_t *devices = NULL;
   unsigned n_devices = 0;
-  int openasuser;
+  int openasuser = 0;
   int should_free_origin = 0;
   int should_free_appid = 0;
   int should_free_auth_file = 0;
   int should_free_authpending_file = 0;
+  PAM_MODUTIL_DEF_PRIVS(privs);
 
   parse_cfg(flags, argc, argv, cfg);
 
@@ -235,6 +237,9 @@
         goto done;
       }
 
+      /* Opening a file in a users $HOME, need to drop privs for security */
+      openasuser = geteuid() == 0 ? 1 : 0;
+
       snprintf(buf, authfile_dir_len,
                "%s/.config%s", pw->pw_dir, DEFAULT_AUTHFILE);
     } else {
@@ -250,9 +255,14 @@
 
       snprintf(buf, authfile_dir_len,
                "%s%s", authfile_dir, DEFAULT_AUTHFILE);
-    }
-
-    DBG("Using default authentication file %s", buf);
+
+      if (!openasuser) {
+	DBG("WARNING: not dropping privileges when reading %s, please "
+	    "consider setting openasuser=1 in the module configuration", buf);
+      }
+    }
+
+    DBG("Using authentication file %s", buf);
 
     cfg->auth_file = buf; /* cfg takes ownership */
     should_free_auth_file = 1;
@@ -261,25 +271,28 @@
     DBG("Using authentication file %s", cfg->auth_file);
   }
 
-  openasuser = geteuid() == 0 && cfg->openasuser;
+  if (!openasuser) {
+    openasuser = geteuid() == 0 && cfg->openasuser;
+  }
   if (openasuser) {
-    if (seteuid(pw_s.pw_uid)) {
-      DBG("Unable to switch user to uid %i", pw_s.pw_uid);
+    DBG("Dropping privileges");
+    if (pam_modutil_drop_priv(pamh, &privs, pw)) {
+      DBG("Unable to switch user to uid %i", pw->pw_uid);
       retval = PAM_IGNORE;
       goto done;
     }
-    DBG("Switched to uid %i", pw_s.pw_uid);
+    DBG("Switched to uid %i", pw->pw_uid);
   }
   retval = get_devices_from_authfile(cfg->auth_file, user, cfg->max_devs,
                                      cfg->debug, cfg->debug_file,
                                      devices, &n_devices);
   if (openasuser) {
-    if (seteuid(0)) {
-      DBG("Unable to switch back to uid 0");
+    if (pam_modutil_regain_priv(pamh, &privs)) {
+      DBG("could not restore privileges");
       retval = PAM_IGNORE;
       goto done;
     }
-    DBG("Switched back to uid 0");
+    DBG("Restored privileges");
   }
 
   if (retval != 1) {
```
