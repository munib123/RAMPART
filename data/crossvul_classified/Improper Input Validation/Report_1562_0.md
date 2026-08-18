# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1562_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1562_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 115-155 of the vulnerable file.

                                      "org.freedesktop.problems.InvalidUser",
                                      error->message);
            g_error_free(error);
        }
        else
        {
            g_dbus_method_invocation_return_dbus_error(invocation,
                                      "org.freedesktop.problems.InvalidUser",
                                      _("Unknown error"));
        }
        return (uid_t) -1;
    }

    g_variant_get(result, "(u)", &caller_uid);
    g_variant_unref(result);

    log_info("Caller uid: %i", caller_uid);
    return caller_uid;
}

static bool allowed_problem_dir(const char *dir_name)
{
//HACK HACK HACK! Disabled for now until we fix clients (abrt-gui) to not pass /home/user/.cache/abrt/spool
#if 0
    unsigned len = strlen(g_settings_dump_location);

    /* If doesn't start with "g_settings_dump_location[/]"... */
    if (strncmp(dir_name, g_settings_dump_location, len) != 0
     || (dir_name[len] != '/' && dir_name[len] != '\0')
    /* or contains "/." anywhere (-> might contain ".." component) */
     || strstr(dir_name + len, "/.")
    ) {
        return false;
    }
#endif
    return true;
}

static char *handle_new_problem(GVariant *problem_info, uid_t caller_uid, char **error)
{
    problem_data_t *pd = problem_data_new();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,18 +132,34 @@
     return caller_uid;
 }
 
-static bool allowed_problem_dir(const char *dir_name)
-{
-//HACK HACK HACK! Disabled for now until we fix clients (abrt-gui) to not pass /home/user/.cache/abrt/spool
+bool allowed_problem_dir(const char *dir_name)
+{
+    if (!dir_is_in_dump_location(dir_name))
+    {
+        error_msg("Bad problem directory name '%s', should start with: '%s'", dir_name, g_settings_dump_location);
+        return false;
+    }
+
+    /* We cannot test correct permissions yet because we still need to chown
+     * dump directories before reporting and Chowing changes the file owner to
+     * the reporter, which causes this test to fail and prevents users from
+     * getting problem data after reporting it.
+     *
+     * Fortunately, libreport has been hardened against hard link and symbolic
+     * link attacks and refuses to work with such files, so this test isn't
+     * really necessary, however, we will use it once we get rid of the
+     * chowning files.
+     *
+     * abrt-server refuses to run post-create on directories that have
+     * incorrect owner (not "root:(abrt|root)"), incorrect permissions (other
+     * bits are not 0) and are complete (post-create finished). So, there is no
+     * way to run security sensitive event scripts (post-create) on crafted
+     * problem directories.
+     */
 #if 0
-    unsigned len = strlen(g_settings_dump_location);
-
-    /* If doesn't start with "g_settings_dump_location[/]"... */
-    if (strncmp(dir_name, g_settings_dump_location, len) != 0
-     || (dir_name[len] != '/' && dir_name[len] != '\0')
-    /* or contains "/." anywhere (-> might contain ".." component) */
-     || strstr(dir_name + len, "/.")
-    ) {
+    if (!dir_has_correct_permissions(dir_name))
+    {
+        error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dir_name);
         return false;
     }
 #endif
```
