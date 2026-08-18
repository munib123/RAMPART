# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3264_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3264_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 787-827 of the vulnerable file.

    }

    c = find_config_next(c, c->next, CONF_PARAM, "DefaultChdir", FALSE);
  }

  /* If the directory is relative, concatenate w/ session.cwd. */
  if (dir != NULL &&
      *dir != '/' &&
      *dir != '~') {
    dir = pdircat(p, session.cwd, dir, NULL);
  }

  /* Check for any expandable variables. */
  if (dir != NULL) {
    dir = path_subst_uservar(p, &dir);
  }

  return dir;
}

/* Determine if the user (non-anon) needs a default root dir other than /. */
static int get_default_root(pool *p, int allow_symlinks, const char **root) {
  config_rec *c = NULL;
  const char *dir = NULL;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "DefaultRoot", FALSE);
  while (c != NULL) {
    pr_signals_handle();

    /* Check the groups acl */
    if (c->argc < 2) {
      dir = c->argv[0];
      break;
    }

    res = pr_expr_eval_group_and(((char **) c->argv)+1);
    if (res) {
      dir = c->argv[0];
      break;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -804,6 +804,59 @@
   return dir;
 }
 
+static int is_symlink_path(pool *p, const char *path, size_t pathlen) {
+  int res, xerrno = 0;
+  struct stat st;
+  char *ptr;
+
+  if (pathlen == 0) {
+    return 0;
+  }
+
+  pr_fs_clear_cache2(path);
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
 /* Determine if the user (non-anon) needs a default root dir other than /. */
 static int get_default_root(pool *p, int allow_symlinks, const char **root) {
   config_rec *c = NULL;
@@ -847,7 +900,6 @@
 
       if (allow_symlinks == FALSE) {
         char *path, target_path[PR_TUNABLE_PATH_MAX + 1];
-        struct stat st;
         size_t pathlen;
 
         /* First, deal with any possible interpolation.  dir_realpath() will
@@ -878,22 +930,13 @@
           path[pathlen-1] = '\0';
         }
 
-        pr_fs_clear_cache2(path);
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
