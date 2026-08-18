# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1566_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1566_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 590-630 of the vulnerable file.

        /* It is OK to call g_variant_new("(a{ss})", NULL) because */
        /* G_VARIANT_TYPE_TUPLE allows NULL value */
        GVariant *response = g_variant_new("(a{ss})", builder);

        if (builder)
            g_variant_builder_unref(builder);

        log_info("GetInfo: returning value for '%s'", problem_dir);
        g_dbus_method_invocation_return_value(invocation, response);
        return;
    }

    if (g_strcmp0(method_name, "SetElement") == 0)
    {
        const char *problem_id;
        const char *element;
        const char *value;

        g_variant_get(parameters, "(&s&s&s)", &problem_id, &element, &value);

        if (!str_is_correct_filename(element))
        {
            log_notice("'%s' is not a valid element name of '%s'", element, problem_id);
            char *error = xasprintf(_("'%s' is not a valid element name"), element);
            g_dbus_method_invocation_return_dbus_error(invocation,
                                              "org.freedesktop.problems.InvalidElement",
                                              error);

            free(error);
            return;
        }

        struct dump_dir *dd = open_directory_for_modification_of_element(
                                    invocation, caller_uid, problem_id, element);
        if (!dd)
            /* Already logged from open_directory_for_modification_of_element() */
            return;

        /* Is it good idea to make it static? Is it possible to change the max size while a single run? */
        const double max_dir_size = g_settings_nMaxCrashReportsSize * (1024 * 1024);
        const long item_size = dd_get_item_size(dd, element);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -607,6 +607,12 @@
 
         g_variant_get(parameters, "(&s&s&s)", &problem_id, &element, &value);
 
+        if (!allowed_problem_dir(problem_id))
+        {
+            return_InvalidProblemDir_error(invocation, problem_id);
+            return;
+        }
+
         if (!str_is_correct_filename(element))
         {
             log_notice("'%s' is not a valid element name of '%s'", element, problem_id);
@@ -665,6 +671,12 @@
         const char *element;
 
         g_variant_get(parameters, "(&s&s)", &problem_id, &element);
+
+        if (!allowed_problem_dir(problem_id))
+        {
+            return_InvalidProblemDir_error(invocation, problem_id);
+            return;
+        }
 
         if (!str_is_correct_filename(element))
         {
@@ -782,6 +794,18 @@
         g_variant_get_child(parameters, 2, "x", &timestamp_from);
         g_variant_get_child(parameters, 3, "x", &timestamp_to);
         g_variant_get_child(parameters, 4, "b", &all);
+
+        if (!str_is_correct_filename(element))
+        {
+            log_notice("'%s' is not a valid element name", element);
+            char *error = xasprintf(_("'%s' is not a valid element name"), element);
+            g_dbus_method_invocation_return_dbus_error(invocation,
+                                              "org.freedesktop.problems.InvalidElement",
+                                              error);
+
+            free(error);
+            return;
+        }
 
         if (all && polkit_check_authorization_dname(caller, "org.freedesktop.problems.getall") == PolkitYes)
             caller_uid = 0;
```
