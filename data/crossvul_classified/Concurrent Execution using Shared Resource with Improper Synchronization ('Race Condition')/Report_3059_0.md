# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3059_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3059_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 351-391 of the vulnerable file.


	  if (pid != (pid_t)-1 && WIFSTOPPED (status))
	    {
	      kill (getpid (), SIGSTOP);
	      /* once we get here, we must have resumed */
	      kill (pid, SIGCONT);
	    }
	  else
	    break;
	}
      if (pid != (pid_t)-1)
        {
          if (WIFSIGNALED (status))
            {
              fprintf (stderr, "%s%s\n", strsignal (WTERMSIG (status)),
                       WCOREDUMP (status) ? _(" (core dumped)") : "");
              status = WTERMSIG (status) + 128;
            }
          else
            status = WEXITSTATUS (status);
        }
      else if (caught_signal)
        status = caught_signal + 128;
      else
        status = 1;
    }
  else
    status = 1;

  if (caught_signal)
    {
      fprintf (stderr, _("\nSession terminated, killing shell..."));
      kill (child, SIGTERM);
    }

  cleanup_pam (PAM_SUCCESS);

  if (caught_signal)
    {
      sleep (2);
      kill (child, SIGKILL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -368,6 +368,9 @@
             }
           else
             status = WEXITSTATUS (status);
+
+	  /* child is gone, don't use the PID anymore */
+	  child = (pid_t) -1;
         }
       else if (caught_signal)
         status = caught_signal + 128;
@@ -377,7 +380,7 @@
   else
     status = 1;
 
-  if (caught_signal)
+  if (caught_signal && child != (pid_t)-1)
     {
       fprintf (stderr, _("\nSession terminated, killing shell..."));
       kill (child, SIGTERM);
@@ -387,9 +390,12 @@
 
   if (caught_signal)
     {
-      sleep (2);
-      kill (child, SIGKILL);
-      fprintf (stderr, _(" ...killed.\n"));
+      if (child != (pid_t)-1)
+	{
+	  sleep (2);
+	  kill (child, SIGKILL);
+	  fprintf (stderr, _(" ...killed.\n"));
+	}
 
       /* Let's terminate itself with the received signal.
        *
```
