# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-38 of the vulnerable file.

/*
  Copyright (C) 2010  ABRT team

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "libabrt.h"

/* Maximal length of backtrace. */
#define MAX_BACKTRACE_SIZE (1024*1024)
/* Amount of data received from one client for a message before reporting error. */
#define MAX_MESSAGE_SIZE (4*MAX_BACKTRACE_SIZE)
/* Maximal number of characters read from socket at once. */
#define INPUT_BUFFER_SIZE (8*1024)
/* We exit after this many seconds */
#define TIMEOUT 10


/*
Unix socket in ABRT daemon for creating new dump directories.

Why to use socket for creating dump dirs? Security. When a Python
script throws unexpected exception, ABRT handler catches it, running
as a part of that broken Python application. The application is running
with certain SELinux privileges, for example it can not execute other
programs, or to create files in /var/cache or anything else required
to properly fill a problem directory. Adding these privileges to every
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
+#include "problem_api.h"
 #include "libabrt.h"
 
 /* Maximal length of backtrace. */
@@ -153,7 +154,36 @@
         error_msg("Bad problem directory name '%s', should start with: '%s'", dirname, g_settings_dump_location);
         return 400; /* Bad Request */
     }
-    if (!dump_dir_accessible_by_uid(dirname, client_uid))
+    if (g_settings_privatereports)
+    {
+        struct stat statbuf;
+        if (lstat(dirname, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
+        {
+            error_msg("Path '%s' isn't directory", dirname);
+            return 404; /* Not Found */
+        }
+        /* Get ABRT's group gid */
+        struct group *gr = getgrnam("abrt");
+        if (!gr)
+        {
+            error_msg("Group 'abrt' does not exist");
+            return 500;
+        }
+        if (statbuf.st_uid != 0 || !(statbuf.st_gid == 0 || statbuf.st_gid == gr->gr_gid) || statbuf.st_mode & 07)
+        {
+            error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dirname);
+            return 403;
+        }
+        struct dump_dir *dd = dd_opendir(dirname, DD_OPEN_READONLY);
+        const bool complete = dd && problem_dump_dir_is_complete(dd);
+        dd_close(dd);
+        if (complete)
+        {
+            error_msg("Problem directory '%s' has already been processed", dirname);
+            return 403;
+        }
+    }
+    else if (!dump_dir_accessible_by_uid(dirname, client_uid))
     {
         if (errno == ENOTDIR)
         {
@@ -377,7 +407,7 @@
     /* No need to check the path length, as all variables used are limited,
      * and dd_create() fails if the path is too long.
      */
-    struct dump_dir *dd = dd_create(path, client_uid, DEFAULT_DUMP_DIR_MODE);
+    struct dump_dir *dd = dd_create(path, g_settings_privatereports ? 0 : client_uid, DEFAULT_DUMP_DIR_MODE);
     if (!dd)
     {
         error_msg_and_die("Error creating problem directory '%s'", path);
```
