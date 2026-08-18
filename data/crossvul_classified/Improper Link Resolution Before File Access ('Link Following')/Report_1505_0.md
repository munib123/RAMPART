# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1505_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1505_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 160-209 of the vulnerable file.

    {
        /* Then refuse to operate on it (someone is attacking us??) */
        error_msg("Bad problem directory name '%s', should start with: '%s'", dirname, g_settings_dump_location);
        return 400; /* Bad Request */
    }
    if (!dir_has_correct_permissions(dirname))
    {
        error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dirname);
        return 400; /*  */
    }
    if (g_settings_privatereports)
    {
        struct dump_dir *dd = dd_opendir(dirname, DD_OPEN_READONLY);
        const bool complete = dd && problem_dump_dir_is_complete(dd);
        dd_close(dd);
        if (complete)
        {
            error_msg("Problem directory '%s' has already been processed", dirname);
            return 403;
        }
    }
    else if (!dump_dir_accessible_by_uid(dirname, client_uid))
    {
        if (errno == ENOTDIR)
        {
            error_msg("Path '%s' isn't problem directory", dirname);
            return 404; /* Not Found */
        }
        error_msg("Problem directory '%s' can't be accessed by user with uid %ld", dirname, (long)client_uid);
        return 403; /* Forbidden */
    }

    int child_stdout_fd;
    int child_pid = spawn_event_handler_child(dirname, "post-create", &child_stdout_fd);

    char *dup_of_dir = NULL;
    struct strbuf *cmd_output = strbuf_new();

    bool child_is_post_create = 1; /* else it is a notify child */

 read_child_output:
    //log("Reading from event fd %d", child_stdout_fd);

    /* Read streamed data and split lines */
    for (;;)
    {
        char buf[250]; /* usually we get one line, no need to have big buf */
        errno = 0;
        int r = safe_read(child_stdout_fd, buf, sizeof(buf) - 1);
        if (r <= 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,16 +178,6 @@
             return 403;
         }
     }
-    else if (!dump_dir_accessible_by_uid(dirname, client_uid))
-    {
-        if (errno == ENOTDIR)
-        {
-            error_msg("Path '%s' isn't problem directory", dirname);
-            return 404; /* Not Found */
-        }
-        error_msg("Problem directory '%s' can't be accessed by user with uid %ld", dirname, (long)client_uid);
-        return 403; /* Forbidden */
-    }
 
     int child_stdout_fd;
     int child_pid = spawn_event_handler_child(dirname, "post-create", &child_stdout_fd);
@@ -741,14 +731,21 @@
     /* Body received, EOF was seen. Don't let alarm to interrupt after this. */
     alarm(0);
 
+    int ret = 0;
     if (url_type == CREATION_NOTIFICATION)
     {
+        if (client_uid != 0)
+        {
+            error_msg("UID=%ld is not authorized to trigger post-create processing", (long)client_uid);
+            ret = 403; /* Forbidden */
+            goto out;
+        }
+
         messagebuf_data[messagebuf_len] = '\0';
         return run_post_create(messagebuf_data);
     }
 
     /* Save problem dir */
-    int ret = 0;
     unsigned pid = convert_pid(problem_info);
     die_if_data_is_missing(problem_info);
 
```
