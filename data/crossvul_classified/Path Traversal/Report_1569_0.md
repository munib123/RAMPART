# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1569_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1569_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 22-62 of the vulnerable file.


#define NEW_PD_SUFFIX ".new"

static struct dump_dir *try_dd_create(const char *base_dir_name, const char *dir_name, uid_t uid)
{
    char *path = concat_path_file(base_dir_name, dir_name);
    struct dump_dir *dd = dd_create(path, uid, DEFAULT_DUMP_DIR_MODE);
    free(path);
    return dd;
}

struct dump_dir *create_dump_dir_from_problem_data(problem_data_t *problem_data, const char *base_dir_name)
{
    INITIALIZE_LIBREPORT();

    char *type = problem_data_get_content_or_NULL(problem_data, FILENAME_ANALYZER);

    if (!type)
    {
        error_msg(_("Missing required item: '%s'"), FILENAME_ANALYZER);
        return NULL;
    }

    uid_t uid = (uid_t)-1L;
    char *uid_str = problem_data_get_content_or_NULL(problem_data, FILENAME_UID);

    if (uid_str)
    {
        char *endptr;
        errno = 0;
        long val = strtol(uid_str, &endptr, 10);

        if (errno != 0 || endptr == uid_str || *endptr != '\0' || INT_MAX < val)
        {
            error_msg(_("uid value is not valid: '%s'"), uid_str);
            return NULL;
        }

        uid = (uid_t)val;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,12 @@
     if (!type)
     {
         error_msg(_("Missing required item: '%s'"), FILENAME_ANALYZER);
+        return NULL;
+    }
+
+    if (!str_is_correct_filename(type))
+    {
+        error_msg(_("'%s' is not correct file name"), FILENAME_ANALYZER);
         return NULL;
     }
 
@@ -105,6 +111,12 @@
     g_hash_table_iter_init(&iter, problem_data);
     while (g_hash_table_iter_next(&iter, (void**)&name, (void**)&value))
     {
+        if (!str_is_correct_filename(name))
+        {
+            error_msg("Problem data field name contains disallowed chars: '%s'", name);
+            continue;
+        }
+
         if (value->flags & CD_FLAG_BIN)
         {
             char *dest = concat_path_file(dd->dd_dirname, name);
@@ -116,13 +128,6 @@
                 log_info("copied %li bytes", (unsigned long)copied);
             free(dest);
 
-            continue;
-        }
-
-        /* only files should contain '/' and those are handled earlier */
-        if (name[0] == '.' || strchr(name, '/'))
-        {
-            error_msg("Problem data field name contains disallowed chars: '%s'", name);
             continue;
         }
 
```
