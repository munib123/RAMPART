# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1351_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1351_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 644-684 of the vulnerable file.

            cmp_func = cmp_S;
        }
    } else if (opt_r) {
        cmp_func = cmp_r;
    } else {
        cmp_func = cmp;
    }
    qsort(files_info, files_info_counter, sizeof files_info[0], cmp_func);

    return files_info;
}

/* have to change to the directory first (speed hack for -R) */
static void listdir(unsigned int depth, int f, void * const tls_fd,
                    const char *name)
{
    PureFileInfo *dir;
    char *names;
    PureFileInfo *s;
    PureFileInfo *r;
    int d;

    if (depth >= max_ls_depth || matches >= max_ls_files) {
        return;
    }
    if ((dir = sreaddir(&names)) == NULL) {
        addreply(226, MSG_CANT_READ_FILE, name);
        return;
    }
    s = dir;
    while (s->name_offset != (size_t) -1) {
        d = 0;
        if (FI_NAME(s)[0] != '.') {
            d = listfile(s, NULL);
        } else if (opt_a) {
            if (FI_NAME(s)[1] == 0 ||
                (FI_NAME(s)[1] == '.' && FI_NAME(s)[2] == 0)) {
                listfile(s, NULL);
            } else {
                d = listfile(s, NULL);
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -661,6 +661,8 @@
     char *names;
     PureFileInfo *s;
     PureFileInfo *r;
+    char *alloca_subdir;
+    size_t sizeof_subdir;
     int d;
 
     if (depth >= max_ls_depth || matches >= max_ls_files) {
@@ -690,14 +692,12 @@
     }
     outputfiles(f, tls_fd);
     r = dir;
+    sizeof_subdir = PATH_MAX + 1U;
+    if ((alloca_subdir = ALLOCA(sizeof_subdir)) == NULL) {
+        goto toomany;
+    }
     while (opt_R && r != s) {
         if (r->name_offset != (size_t) -1 && !chdir(FI_NAME(r))) {
-            char *alloca_subdir;
-            const size_t sizeof_subdir = PATH_MAX + 1U;
-
-            if ((alloca_subdir = ALLOCA(sizeof_subdir)) == NULL) {
-                goto toomany;
-            }
             if (SNCHECK(snprintf(alloca_subdir, sizeof_subdir, "%s/%s",
                                  name, FI_NAME(r)), sizeof_subdir)) {
                 goto nolist;
@@ -706,8 +706,8 @@
             wrstr(f, tls_fd, alloca_subdir);
             wrstr(f, tls_fd, ":\r\n\r\n");
             listdir(depth + 1U, f, tls_fd, alloca_subdir);
+
             nolist:
-            ALLOCA_FREE(alloca_subdir);
             if (matches >= max_ls_files) {
                 goto toomany;
             }
@@ -720,6 +720,7 @@
         r++;
     }
     toomany:
+    ALLOCA_FREE(alloca_subdir);
     free(names);
     free(dir);
     names = NULL;
```
