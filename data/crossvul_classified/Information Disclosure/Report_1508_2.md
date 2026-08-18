# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 665-705 of the vulnerable file.


    sprintf(path, "/proc/%lu/status", (long)pid);
    proc_pid_status = xmalloc_xopen_read_close(path, /*maxsz:*/ NULL);

    uid_t fsuid = uid;
    uid_t tmp_fsuid = get_fsuid();
    int suid_policy = dump_suid_policy();
    if (tmp_fsuid != uid)
    {
        /* use root for suided apps unless it's explicitly set to UNSAFE */
        fsuid = 0;
        if (suid_policy == DUMP_SUID_UNSAFE)
            fsuid = tmp_fsuid;
        else
        {
            g_user_core_flags = O_EXCL;
            g_need_nonrelative = 1;
        }
    }

    /* Open a fd to compat coredump, if requested and is possible */
    if (setting_MakeCompatCore && ulimit_c != 0)
        /* note: checks "user_pwd == NULL" inside; updates core_basename */
        user_core_fd = open_user_core(uid, fsuid, pid, &argv[1]);

    if (executable == NULL)
    {
        /* readlink on /proc/$PID/exe failed, don't create abrt dump dir */
        error_msg("Can't read /proc/%lu/exe link", (long)pid);
        goto create_user_core;
    }

    const char *signame = NULL;
    switch (signal_no)
    {
        case SIGILL : signame = "ILL" ; break;
        case SIGFPE : signame = "FPE" ; break;
        case SIGSEGV: signame = "SEGV"; break;
        case SIGBUS : signame = "BUS" ; break; //Bus error (bad memory access)
        case SIGABRT: signame = "ABRT"; break; //usually when abort() was called
    // We have real-world reports from users who see buggy programs
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -682,6 +682,9 @@
         }
     }
 
+    /* If PrivateReports is on, root owns all problem directories */
+    const uid_t dduid = g_settings_privatereports ? 0 : fsuid;
+
     /* Open a fd to compat coredump, if requested and is possible */
     if (setting_MakeCompatCore && ulimit_c != 0)
         /* note: checks "user_pwd == NULL" inside; updates core_basename */
@@ -773,18 +776,19 @@
         goto create_user_core;
     }
 
-    /* use fsuid instead of uid, so we don't expose any sensitive
-     * information of suided app in /var/tmp/abrt
+    /* use dduid (either fsuid or 0) instead of uid, so we don't expose any
+     * sensitive information of suided app in /var/tmp/abrt
      *
      * dd_create_skeleton() creates a new directory and leaves ownership to
      * the current user, hence, we have to call dd_reset_ownership() after the
      * directory is populated.
      */
-    dd = dd_create_skeleton(path, fsuid, DEFAULT_DUMP_DIR_MODE, /*no flags*/0);
+    dd = dd_create_skeleton(path, dduid, DEFAULT_DUMP_DIR_MODE, /*no flags*/0);
     if (dd)
     {
         char *rootdir = get_rootdir(pid);
 
+        /* This function uses fsuid only for its value. The function stores fsuid in a file name 'uid'*/
         dd_create_basic_files(dd, fsuid, NULL);
 
         char source_filename[sizeof("/proc/%lu/somewhat_long_name") + sizeof(long)*3];
```
