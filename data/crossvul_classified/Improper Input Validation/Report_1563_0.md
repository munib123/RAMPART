# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1563_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1563_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 228-268 of the vulnerable file.

    static const char *const protected_elements[] = {
        FILENAME_TIME,
        FILENAME_UID,
        NULL,
    };

    for (const char *const *protected = protected_elements; *protected; ++protected)
    {
        if (strcmp(*protected, element) == 0)
        {
            log_notice("'%s' element of '%s' can't be modified", element, problem_id);
            char *error = xasprintf(_("'%s' element can't be modified"), element);
            g_dbus_method_invocation_return_dbus_error(invocation,
                                        "org.freedesktop.problems.ProtectedElement",
                                        error);
            free(error);
            return NULL;
        }
    }

    if (!dump_dir_accessible_by_uid(problem_id, caller_uid))
    {
        if (errno == ENOTDIR)
        {
            log_notice("'%s' is not a valid problem directory", problem_id);
            return_InvalidProblemDir_error(invocation, problem_id);
        }
        else
        {
            log_notice("UID(%d) is not Authorized to access '%s'", caller_uid, problem_id);
            g_dbus_method_invocation_return_dbus_error(invocation,
                                "org.freedesktop.problems.AuthFailure",
                                _("Not Authorized"));
        }

        return NULL;
    }

    struct dump_dir *dd = dd_opendir(problem_id, /* flags : */ 0);
    if (!dd)
    {   /* This should not happen because of the access check above */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,7 +245,15 @@
         }
     }
 
-    if (!dump_dir_accessible_by_uid(problem_id, caller_uid))
+    int dir_fd = dd_openfd(problem_id);
+    if (dir_fd < 0)
+    {
+        perror_msg("can't open problem directory '%s'", problem_id);
+        return_InvalidProblemDir_error(invocation, problem_id);
+        return NULL;
+    }
+
+    if (!fdump_dir_accessible_by_uid(dir_fd, caller_uid))
     {
         if (errno == ENOTDIR)
         {
@@ -260,10 +268,11 @@
                                 _("Not Authorized"));
         }
 
+        close(dir_fd);
         return NULL;
     }
 
-    struct dump_dir *dd = dd_opendir(problem_id, /* flags : */ 0);
+    struct dump_dir *dd = dd_fdopendir(dir_fd, problem_id, /* flags : */ 0);
     if (!dd)
     {   /* This should not happen because of the access check above */
         log_notice("Can't access the problem '%s' for modification", problem_id);
@@ -429,7 +438,15 @@
             return;
         }
 
-        int ddstat = dump_dir_stat_for_uid(problem_dir, caller_uid);
+        int dir_fd = dd_openfd(problem_dir);
+        if (dir_fd < 0)
+        {
+            perror_msg("can't open problem directory '%s'", problem_dir);
+            return_InvalidProblemDir_error(invocation, problem_dir);
+            return;
+        }
+
+        int ddstat = fdump_dir_stat_for_uid(dir_fd, caller_uid);
         if (ddstat < 0)
         {
             if (errno == ENOTDIR)
@@ -443,6 +460,7 @@
 
             return_InvalidProblemDir_error(invocation, problem_dir);
 
+            close(dir_fd);
             return;
         }
 
@@ -450,6 +468,7 @@
         {   //caller seems to be in group with access to this dir, so no action needed
             log_notice("caller has access to the requested directory %s", problem_dir);
             g_dbus_method_invocation_return_value(invocation, NULL);
+            close(dir_fd);
             return;
         }
 
@@ -460,10 +479,11 @@
             g_dbus_method_invocation_return_dbus_error(invocation,
                                               "org.freedesktop.problems.AuthFailure",
                                               _("Not Authorized"));
-            return;
-        }
-
-        struct dump_dir *dd = dd_opendir(problem_dir, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES);
+            close(dir_fd);
+            return;
+        }
+
+        struct dump_dir *dd = dd_fdopendir(dir_fd, problem_dir, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES);
         if (!dd)
         {
             return_InvalidProblemDir_error(invocation, problem_dir);
@@ -497,12 +517,21 @@
             return;
         }
 
-        if (!dump_dir_accessible_by_uid(problem_dir, caller_uid))
+        int dir_fd = dd_openfd(problem_dir);
+        if (dir_fd < 0)
+        {
+            perror_msg("can't open problem directory '%s'", problem_dir);
+            return_InvalidProblemDir_error(invocation, problem_dir);
+            return;
+        }
+
+        if (!fdump_dir_accessible_by_uid(dir_fd, caller_uid))
         {
             if (errno == ENOTDIR)
             {
                 log_notice("Requested directory does not exist '%s'", problem_dir);
                 return_InvalidProblemDir_error(invocation, problem_dir);
+                close(dir_fd);
                 return;
             }
 
@@ -512,11 +541,12 @@
                 g_dbus_method_invocation_return_dbus_error(invocation,
                                                   "org.freedesktop.problems.AuthFailure",
                                                   _("Not Authorized"));
+                close(dir_fd);
                 return;
             }
         }
 
-        struct dump_dir *dd = dd_opendir(problem_dir, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES);
+        struct dump_dir *dd = dd_fdopendir(dir_fd, problem_dir, DD_OPEN_READONLY | DD_FAIL_QUIETLY_EACCES);
         if (!dd)
         {
             return_InvalidProblemDir_error(invocation, problem_dir);
@@ -677,20 +707,40 @@
         for (GList *l = problem_dirs; l; l = l->next)
         {
             const char *dir_name = (const char*)l->data;
-            if (!dump_dir_accessible_by_uid(dir_name, caller_uid))
+
+            int dir_fd = dd_openfd(dir_name);
+            if (dir_fd < 0)
+            {
+                perror_msg("can't open problem directory '%s'", dir_name);
+                return_InvalidProblemDir_error(invocation, dir_name);
+                return;
+            }
+
+            if (!fdump_dir_accessible_by_uid(dir_fd, caller_uid))
             {
                 if (errno == ENOTDIR)
                 {
                     log_notice("Requested directory does not exist '%s'", dir_name);
+                    close(dir_fd);
                     continue;
                 }
 
                 if (polkit_check_authorization_dname(caller, "org.freedesktop.problems.getall") != PolkitYes)
                 { // if user didn't provide correct credentials, just move to the next dir
+                    close(dir_fd);
                     continue;
                 }
             }
-            delete_dump_dir(dir_name);
+
+            struct dump_dir *dd = dd_fdopendir(dir_fd, dir_name, /*flags:*/ 0);
+            if (dd)
+            {
+                if (dd_delete(dd) != 0)
+                {
+                    error_msg("Failed to delete problem directory '%s'", dir_name);
+                    dd_close(dd);
+                }
+            }
         }
 
         g_dbus_method_invocation_return_value(invocation, NULL);
```
