# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1569_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1569_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 328-368 of the vulnerable file.


        unsigned dirname_len = strlen(dd->dd_dirname);
        char lock_buf[dirname_len + sizeof("/.lock")];
        strcpy(lock_buf, dd->dd_dirname);
        strcpy(lock_buf + dirname_len, "/.lock");
        xunlink(lock_buf);

        log_info("Unlocked '%s'", lock_buf);
    }
}

static inline struct dump_dir *dd_init(void)
{
    struct dump_dir* dd = (struct dump_dir*)xzalloc(sizeof(struct dump_dir));
    dd->dd_time = -1;
    return dd;
}

int dd_exist(const struct dump_dir *dd, const char *path)
{
    char *full_path = concat_path_file(dd->dd_dirname, path);
    int ret = exist_file_dir(full_path);
    free(full_path);
    return ret;
}

void dd_close(struct dump_dir *dd)
{
    if (!dd)
        return;

    dd_unlock(dd);
    if (dd->next_dir)
    {
        closedir(dd->next_dir);
        /* free(dd->next_dir); - WRONG! */
    }

    free(dd->dd_type);
    free(dd->dd_dirname);
    free(dd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -345,6 +345,9 @@
 
 int dd_exist(const struct dump_dir *dd, const char *path)
 {
+    if (!str_is_correct_filename(path))
+        error_msg_and_die("Cannot test existence. '%s' is not a valid file name", path);
+
     char *full_path = concat_path_file(dd->dd_dirname, path);
     int ret = exist_file_dir(full_path);
     free(full_path);
@@ -1044,6 +1047,13 @@
 //    if (!dd->locked)
 //        error_msg_and_die("dump_dir is not opened"); /* bug */
 
+    if (!str_is_correct_filename(name))
+    {
+        error_msg("Cannot load text. '%s' is not a valid file name", name);
+        if (!(flags & DD_LOAD_TEXT_RETURN_NULL_ON_FAILURE))
+            xfunc_die();
+    }
+
     /* Compat with old abrt dumps. Remove in abrt-2.1 */
     if (strcmp(name, "release") == 0)
         name = FILENAME_OS_RELEASE;
@@ -1065,6 +1075,9 @@
     if (!dd->locked)
         error_msg_and_die("dump_dir is not opened"); /* bug */
 
+    if (!str_is_correct_filename(name))
+        error_msg_and_die("Cannot save text. '%s' is not a valid file name", name);
+
     char *full_path = concat_path_file(dd->dd_dirname, name);
     save_binary_file(full_path, data, strlen(data), dd->dd_uid, dd->dd_gid, dd->mode);
     free(full_path);
@@ -1075,6 +1088,9 @@
     if (!dd->locked)
         error_msg_and_die("dump_dir is not opened"); /* bug */
 
+    if (!str_is_correct_filename(name))
+        error_msg_and_die("Cannot save binary. '%s' is not a valid file name", name);
+
     char *full_path = concat_path_file(dd->dd_dirname, name);
     save_binary_file(full_path, data, size, dd->dd_uid, dd->dd_gid, dd->mode);
     free(full_path);
@@ -1082,6 +1098,9 @@
 
 long dd_get_item_size(struct dump_dir *dd, const char *name)
 {
+    if (!str_is_correct_filename(name))
+        error_msg_and_die("Cannot get item size. '%s' is not a valid file name", name);
+
     long size = -1;
     char *iname = concat_path_file(dd->dd_dirname, name);
     struct stat statbuf;
@@ -1105,6 +1124,9 @@
 {
     if (!dd->locked)
         error_msg_and_die("dump_dir is not opened"); /* bug */
+
+    if (!str_is_correct_filename(name))
+        error_msg_and_die("Cannot delete item. '%s' is not a valid file name", name);
 
     char *path = concat_path_file(dd->dd_dirname, name);
     int res = unlink(path);
```
