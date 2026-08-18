# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1670_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1670_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 91-132 of the vulnerable file.

            perror_msg_and_die("setregid(egid, rgid)");

        if (setreuid(euid, ruid) < 0)
            perror_msg_and_die("setreuid(euid, ruid)");

        const int build_ids_fd = open(build_ids, O_RDONLY);

        if (setregid(rgid, egid) < 0)
            perror_msg_and_die("setregid(rgid, egid)");

        if (setreuid(ruid, euid) < 0 )
            perror_msg_and_die("setreuid(ruid, euid)");

        if (build_ids_fd < 0)
            perror_msg_and_die("Failed to open file '%s'", build_ids);

        /* We are not going to free this memory. There is no place to do so. */
        build_ids_self_fd = xasprintf("/proc/self/fd/%d", build_ids_fd);
    }

    /* name, -v, --ids, -, -y, -e, EXACT, -r, REPO, --, NULL */
    const char *args[11];
    {
        const char *verbs[] = { "", "-v", "-vv", "-vvv" };
        unsigned i = 0;
        args[i++] = EXECUTABLE;
        args[i++] = "--ids";
        args[i++] = (build_ids_self_fd != NULL) ? build_ids_self_fd : "-";
        if (g_verbose > 0)
            args[i++] = verbs[g_verbose <= 3 ? g_verbose : 3];
        if ((opts & OPT_y))
            args[i++] = "-y";
        if ((opts & OPT_e))
        {
            args[i++] = "--exact";
            args[i++] = exact;
        }
        if ((opts & OPT_r))
        {
            args[i++] = "--repo";
            args[i++] = repo;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,8 +108,14 @@
         build_ids_self_fd = xasprintf("/proc/self/fd/%d", build_ids_fd);
     }
 
-    /* name, -v, --ids, -, -y, -e, EXACT, -r, REPO, --, NULL */
-    const char *args[11];
+    char tmp_directory[] = LARGE_DATA_TMP_DIR"/abrt-tmp-debuginfo.XXXXXX";
+    if (mkdtemp(tmp_directory) == NULL)
+        perror_msg_and_die("Failed to create working directory");
+
+    log_info("Created working directory: %s", tmp_directory);
+
+    /* name, -v, --ids, -, -y, -e, EXACT, -r, REPO, -t, PATH, --, NULL */
+    const char *args[13];
     {
         const char *verbs[] = { "", "-v", "-vv", "-vvv" };
         unsigned i = 0;
@@ -130,6 +136,8 @@
             args[i++] = "--repo";
             args[i++] = repo;
         }
+        args[i++] = "--tmpdir";
+        args[i++] = tmp_directory;
         args[i++] = "--";
         args[i] = NULL;
     }
@@ -204,6 +212,31 @@
         umask(0022);
     }
 
-    execvp(EXECUTABLE, (char **)args);
-    error_msg_and_die("Can't execute %s", EXECUTABLE);
+    pid_t pid = fork();
+    if (pid < 0)
+        perror_msg_and_die("fork");
+
+    if (pid == 0)
+    {
+        execvp(EXECUTABLE, (char **)args);
+        error_msg_and_die("Can't execute %s", EXECUTABLE);
+    }
+
+    int status;
+    if (safe_waitpid(pid, &status, 0) < 0)
+        perror_msg_and_die("waitpid");
+
+    if (rmdir(tmp_directory) >= 0)
+        log_info("Removed working directory: %s", tmp_directory);
+    else if (errno != ENOENT)
+        perror_msg("Failed to remove working directory");
+
+    /* Normal execution should exit here. */
+    if (WIFEXITED(status))
+        return WEXITSTATUS(status);
+
+    if (WIFSIGNALED(status))
+        error_msg_and_die("Child terminated with signal %d", WTERMSIG(status));
+
+    error_msg_and_die("Child exit failed");
 }
```
