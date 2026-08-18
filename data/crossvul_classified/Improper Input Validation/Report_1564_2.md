# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1564_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1564_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 410-429 of the vulnerable file.

{
    load_abrt_conf();

    struct dump_dir *dd = NULL;

    if (g_settings_privatereports)
        dd = create_dump_dir_from_problem_data_ext(pd, g_settings_dump_location, 0);
    else
        dd = create_dump_dir_from_problem_data(pd, g_settings_dump_location);

    char *problem_id = NULL;
    if (dd)
    {
        problem_id = xstrdup(dd->dd_dirname);
        dd_close(dd);
    }

    log_info("problem id: '%s'", problem_id);
    return problem_id;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -427,3 +427,59 @@
     log_info("problem id: '%s'", problem_id);
     return problem_id;
 }
+
+bool dir_is_in_dump_location(const char *dir_name)
+{
+    unsigned len = strlen(g_settings_dump_location);
+
+    /* The path must start with "g_settings_dump_location" */
+    if (strncmp(dir_name, g_settings_dump_location, len) != 0)
+    {
+        log_debug("Bad parent directory: '%s' not in '%s'", g_settings_dump_location, dir_name);
+        return false;
+    }
+
+    /* and must be a sub-directory of the g_settings_dump_location dir */
+    const char *base_name = dir_name + len;
+    while (*base_name && *base_name == '/')
+        ++base_name;
+
+    if (*(base_name - 1) != '/' || !str_is_correct_filename(base_name))
+    {
+        log_debug("Invalid dump directory name: '%s'", base_name);
+        return false;
+    }
+
+    /* and we are sure it is a directory */
+    struct stat sb;
+    if (lstat(dir_name, &sb) < 0)
+    {
+        VERB2 perror_msg("stat('%s')", dir_name);
+        return errno== ENOENT;
+    }
+
+    return S_ISDIR(sb.st_mode);
+}
+
+bool dir_has_correct_permissions(const char *dir_name)
+{
+    if (g_settings_privatereports)
+    {
+        struct stat statbuf;
+        if (lstat(dir_name, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
+        {
+            error_msg("Path '%s' isn't directory", dir_name);
+            return false;
+        }
+        /* Get ABRT's group gid */
+        struct group *gr = getgrnam("abrt");
+        if (!gr)
+        {
+            error_msg("Group 'abrt' does not exist");
+            return false;
+        }
+        if (statbuf.st_uid != 0 || !(statbuf.st_gid == 0 || statbuf.st_gid == gr->gr_gid) || statbuf.st_mode & 07)
+            return false;
+    }
+    return true;
+}
```
