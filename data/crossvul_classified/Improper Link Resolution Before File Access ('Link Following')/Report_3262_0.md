# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3262_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3262_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2016 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
  * ProFTPD - FTP server daemon
  * Copyright (c) 1997, 1998 Public Flood Software
  * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
- * Copyright (c) 2001-2016 The ProFTPD Project team
+ * Copyright (c) 2001-2017 The ProFTPD Project team
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
@@ -688,9 +688,66 @@
   return dir;
 }
 
-/* Determine if the user (non-anon) needs a default root dir other than /.
- */
-
+static int is_symlink_path(pool *p, const char *path, size_t pathlen) {
+  int res, xerrno = 0;
+  struct stat st;
+  char *ptr;
+
+  if (pathlen == 0) {
+    return 0;
+  }
+
+  pr_fs_clear_cache();
+  res = pr_fsio_lstat(path, &st);
+  if (res < 0) {
+    xerrno = errno;
+
+    pr_log_pri(PR_LOG_WARNING, "error: unable to check %s: %s", path,
+      strerror(xerrno));
+
+    errno = xerrno;
+    return -1;
+  }
+
+  if (S_ISLNK(st.st_mode)) {
+    errno = EPERM;
+    return -1;
+  }
+
+  /* To handle the case where a component further up the path might be a
+   * symlink (which lstat(2) will NOT handle), we walk the path backwards,
+   * calling ourselves recursively.
+   */
+
+  ptr = strrchr(path, '/');
+  if (ptr != NULL) {
+    char *new_path;
+    size_t new_pathlen;
+
+    pr_signals_handle();
+
+    new_pathlen = ptr - path;
+
+    /* Make sure our pointer actually changed position. */
+    if (new_pathlen == pathlen) {
+      return 0;
+    }
+
+    new_path = pstrndup(p, path, new_pathlen);
+
+    pr_log_debug(DEBUG10,
+      "AllowChrootSymlink: path '%s' not a symlink, checking '%s'", path,
+      new_path);
+    res = is_symlink_path(p, new_path, new_pathlen);
+    if (res < 0) {
+      return -1;
+    }
+  }
+
+  return 0;
+}
+
+/* Determine if the user (non-anon) needs a default root dir other than /. */
 static int get_default_root(pool *p, int allow_symlinks, char **root) {
   config_rec *c = NULL;
   char *dir = NULL;
@@ -733,7 +790,6 @@
 
       if (allow_symlinks == FALSE) {
         char *path, target_path[PR_TUNABLE_PATH_MAX + 1];
-        struct stat st;
         size_t pathlen;
 
         /* First, deal with any possible interpolation.  dir_realpath() will
@@ -764,22 +820,13 @@
           path[pathlen-1] = '\0';
         }
 
-        pr_fs_clear_cache();
-        res = pr_fsio_lstat(path, &st);
+        res = is_symlink_path(p, path, pathlen);
         if (res < 0) {
-          xerrno = errno;
-
-          pr_log_pri(PR_LOG_WARNING, "error: unable to check %s: %s", path,
-            strerror(xerrno));
-
-          errno = xerrno;
-          return -1;
-        }
-
-        if (S_ISLNK(st.st_mode)) {
-          pr_log_pri(PR_LOG_WARNING,
-            "error: DefaultRoot %s is a symlink (denied by AllowChrootSymlinks "
-            "config)", path);
+          if (errno == EPERM) {
+            pr_log_pri(PR_LOG_WARNING, "error: DefaultRoot %s is a symlink "
+              "(denied by AllowChrootSymlinks config)", path);
+          }
+
           errno = EPERM;
           return -1;
         }
```
