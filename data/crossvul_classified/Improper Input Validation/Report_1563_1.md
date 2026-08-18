# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1563_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1563_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 29-69 of the vulnerable file.

                        uid_t caller_uid,
                        int (*callback)(struct dump_dir *dd, void *arg),
                        void *arg)
{
    DIR *dp = opendir(path);
    if (!dp)
    {
        /* We don't want to yell if, say, $XDG_CACHE_DIR/abrt/spool doesn't exist */
        //perror_msg("Can't open directory '%s'", path);
        return 0;
    }

    int brk = 0;
    struct dirent *dent;
    while ((dent = readdir(dp)) != NULL)
    {
        if (dot_or_dotdot(dent->d_name))
            continue; /* skip "." and ".." */

        char *full_name = concat_path_file(path, dent->d_name);
        if (caller_uid == -1 || dump_dir_accessible_by_uid(full_name, caller_uid))
        {
            /* Silently ignore *any* errors, not only EACCES.
             * We saw "lock file is locked by process PID" error
             * when we raced with wizard.
             */
            int sv_logmode = logmode;
            logmode = 0;
            struct dump_dir *dd = dd_opendir(full_name, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES | DD_DONT_WAIT_FOR_LOCK);
            logmode = sv_logmode;
            if (dd)
            {
                brk = callback ? callback(dd, arg) : 0;
                dd_close(dd);
            }
        }
        free(full_name);
        if (brk)
            break;
    }
    closedir(dp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,15 @@
             continue; /* skip "." and ".." */
 
         char *full_name = concat_path_file(path, dent->d_name);
-        if (caller_uid == -1 || dump_dir_accessible_by_uid(full_name, caller_uid))
+
+        int dir_fd = dd_openfd(full_name);
+        if (dir_fd < 0)
+        {
+            VERB2 perror_msg("can't open problem directory '%s'", full_name);
+            continue;
+        }
+
+        if (caller_uid == -1 || fdump_dir_accessible_by_uid(dir_fd, caller_uid))
         {
             /* Silently ignore *any* errors, not only EACCES.
              * We saw "lock file is locked by process PID" error
@@ -54,7 +62,7 @@
              */
             int sv_logmode = logmode;
             logmode = 0;
-            struct dump_dir *dd = dd_opendir(full_name, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES | DD_DONT_WAIT_FOR_LOCK);
+            struct dump_dir *dd = dd_fdopendir(dir_fd, full_name, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES | DD_DONT_WAIT_FOR_LOCK);
             logmode = sv_logmode;
             if (dd)
             {
@@ -62,6 +70,9 @@
                 dd_close(dd);
             }
         }
+        else
+            close(dir_fd);
+
         free(full_name);
         if (brk)
             break;
```
