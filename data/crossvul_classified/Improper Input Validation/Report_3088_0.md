# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3088_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3088_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2054-2081 of the vulnerable file.

              dont_close[j++] = opt_sync_fd;
            dont_close[j++] = -1;
            fdwalk (proc_fd, close_extra_fds, dont_close);
          }

          return do_init (event_fd, pid);
        }
    }

  __debug__ (("launch executable %s\n", argv[0]));

  if (proc_fd != -1)
    close (proc_fd);

  if (opt_sync_fd != -1)
    close (opt_sync_fd);

  /* We want sigchild in the child */
  unblock_sigchild ();

  if (label_exec (opt_exec_label) == -1)
    die_with_error ("label_exec %s", argv[0]);

  if (execvp (argv[0], argv) == -1)
    die_with_error ("execvp %s", argv[0]);

  return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2071,6 +2071,9 @@
   /* We want sigchild in the child */
   unblock_sigchild ();
 
+  if (setsid () == (pid_t) -1)
+    die_with_error ("setsid");
+
   if (label_exec (opt_exec_label) == -1)
     die_with_error ("label_exec %s", argv[0]);
 
```
