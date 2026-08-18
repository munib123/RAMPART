# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1506_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1506_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 151-191 of the vulnerable file.

     * chowning files.
     *
     * abrt-server refuses to run post-create on directories that have
     * incorrect owner (not "root:(abrt|root)"), incorrect permissions (other
     * bits are not 0) and are complete (post-create finished). So, there is no
     * way to run security sensitive event scripts (post-create) on crafted
     * problem directories.
     */
#if 0
    if (!dir_has_correct_permissions(dir_name))
    {
        error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dir_name);
        return false;
    }
#endif
    return true;
}

static char *handle_new_problem(GVariant *problem_info, uid_t caller_uid, char **error)
{
    problem_data_t *pd = problem_data_new();

    GVariantIter *iter;
    g_variant_get(problem_info, "a{ss}", &iter);
    gchar *key, *value;
    while (g_variant_iter_loop(iter, "{ss}", &key, &value))
    {
        problem_data_add_text_editable(pd, key, value);
    }

    if (caller_uid != 0 || problem_data_get_content_or_NULL(pd, FILENAME_UID) == NULL)
    {   /* set uid field to caller's uid if caller is not root or root doesn't pass own uid */
        log_info("Adding UID %d to problem data", caller_uid);
        char buf[sizeof(uid_t) * 3 + 2];
        snprintf(buf, sizeof(buf), "%d", caller_uid);
        problem_data_add_text_noteditable(pd, FILENAME_UID, buf);
    }

    /* At least it should generate local problem identifier UUID */
    problem_data_add_basics(pd);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,6 +168,7 @@
 
 static char *handle_new_problem(GVariant *problem_info, uid_t caller_uid, char **error)
 {
+    char *problem_id = NULL;
     problem_data_t *pd = problem_data_new();
 
     GVariantIter *iter;
@@ -175,6 +176,12 @@
     gchar *key, *value;
     while (g_variant_iter_loop(iter, "{ss}", &key, &value))
     {
+        if (allowed_new_user_problem_entry(caller_uid, key, value) == false)
+        {
+            *error = xasprintf("You are not allowed to create element '%s' containing '%s'", key, value);
+            goto finito;
+        }
+
         problem_data_add_text_editable(pd, key, value);
     }
 
@@ -189,12 +196,13 @@
     /* At least it should generate local problem identifier UUID */
     problem_data_add_basics(pd);
 
-    char *problem_id = problem_data_save(pd);
+    problem_id = problem_data_save(pd);
     if (problem_id)
         notify_new_path(problem_id);
     else if (error)
         *error = xasprintf("Cannot create a new problem");
 
+finito:
     problem_data_free(pd);
     return problem_id;
 }
```
