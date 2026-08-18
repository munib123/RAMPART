# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 393-424 of the vulnerable file.

            full = "";
        }
    }

    if (auto_load_base_index > 0)
    {
        free(args[auto_load_base_index]);
        free(args[auto_load_base_index + 2]);
    }

    free(args[debug_dir_cmd_index]);
    free(args[file_cmd_index]);
    free(args[core_cmd_index]);
    return bt;
}

char* problem_data_save(problem_data_t *pd)
{
    load_abrt_conf();

    struct dump_dir *dd = create_dump_dir_from_problem_data(pd, g_settings_dump_location);

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
@@ -410,7 +410,12 @@
 {
     load_abrt_conf();
 
-    struct dump_dir *dd = create_dump_dir_from_problem_data(pd, g_settings_dump_location);
+    struct dump_dir *dd = NULL;
+
+    if (g_settings_privatereports)
+        dd = create_dump_dir_from_problem_data_ext(pd, g_settings_dump_location, 0);
+    else
+        dd = create_dump_dir_from_problem_data(pd, g_settings_dump_location);
 
     char *problem_id = NULL;
     if (dd)
```
