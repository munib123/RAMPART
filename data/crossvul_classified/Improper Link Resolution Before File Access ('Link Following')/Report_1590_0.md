# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1590_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1590_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 778-818 of the vulnerable file.

            {
                xchdir(user_pwd);
                unlink(core_basename);
            }
            /* copyfd_sparse logs the error including errno string,
             * but it does not log file name */
            error_msg_and_die("Error writing '%s'", path);
        }
        if (user_core_fd >= 0
            /* error writing user coredump? */
         && (fsync(user_core_fd) != 0 || close(user_core_fd) != 0
            /* user coredump is too big? */
            || (ulimit_c == 0 /* paranoia */ || core_size > ulimit_c)
            )
        ) {
            /* nuke it (silently) */
            xchdir(user_pwd);
            unlink(core_basename);
        }

        /* Save JVM crash log if it exists. (JVM's coredump per se
         * is nearly useless for JVM developers)
         */
        {
            char *java_log = xasprintf("/tmp/jvm-%lu/hs_error.log", (long)pid);
            int src_fd = open(java_log, O_RDONLY);
            free(java_log);

            /* If we couldn't open the error log in /tmp directory we can try to
             * read the log from the current directory. It may produce AVC, it
             * may produce some error log but all these are expected.
             */
            if (src_fd < 0)
            {
                java_log = xasprintf("%s/hs_err_pid%lu.log", user_pwd, (long)pid);
                src_fd = open(java_log, O_RDONLY);
                free(java_log);
            }

            if (src_fd >= 0)
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -795,6 +795,8 @@
             unlink(core_basename);
         }
 
+/* Because of #1211835 and #1126850 */
+#if 0
         /* Save JVM crash log if it exists. (JVM's coredump per se
          * is nearly useless for JVM developers)
          */
@@ -827,6 +829,7 @@
                 close(src_fd);
             }
         }
+#endif
 
         /* We close dumpdir before we start catering for crash storm case.
          * Otherwise, delete_dump_dir's from other concurrent
```
