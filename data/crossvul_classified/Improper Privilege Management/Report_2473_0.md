# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 2473_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2473_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 820-860 of the vulnerable file.

      if (opt_sandbox_gid != real_gid && setgid (opt_sandbox_gid) < 0)
        die_with_error ("unable to switch to gid %d", opt_sandbox_gid);
    }

  if (!is_privileged)
    return;

  /* Tell kernel not clear capabilities when later dropping root uid */
  if (prctl (PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_KEEPCAPS) failed");

  if (setuid (opt_sandbox_uid) < 0)
    die_with_error ("unable to drop root uid");

  /* Regain effective required capabilities from permitted */
  set_required_caps ();
}

/* Call setuid() and use capset() to adjust capabilities */
static void
drop_privs (bool keep_requested_caps)
{
  assert (!keep_requested_caps || !is_privileged);
  /* Drop root uid */
  if (geteuid () == 0 && setuid (opt_sandbox_uid) < 0)
    die_with_error ("unable to drop root uid");

  drop_all_caps (keep_requested_caps);

  /* We don't have any privs now, so mark us dumpable which makes /proc/self be owned by the user instead of root */
  if (prctl (PR_SET_DUMPABLE, 1, 0, 0, 0) != 0)
    die_with_error ("can't set dumpable");
}

static char *
get_newroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/newroot/", path);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -837,11 +837,13 @@
 
 /* Call setuid() and use capset() to adjust capabilities */
 static void
-drop_privs (bool keep_requested_caps)
+drop_privs (bool keep_requested_caps,
+            bool already_changed_uid)
 {
   assert (!keep_requested_caps || !is_privileged);
   /* Drop root uid */
-  if (geteuid () == 0 && setuid (opt_sandbox_uid) < 0)
+  if (is_privileged && !already_changed_uid &&
+      setuid (opt_sandbox_uid) < 0)
     die_with_error ("unable to drop root uid");
 
   drop_all_caps (keep_requested_caps);
@@ -2299,6 +2301,9 @@
   if (opt_userns_fd != -1 && is_privileged)
     die ("--userns doesn't work in setuid mode");
 
+  if (opt_userns2_fd != -1 && is_privileged)
+    die ("--userns2 doesn't work in setuid mode");
+
   /* We have to do this if we weren't installed setuid (and we're not
    * root), so let's just DWIM */
   if (!is_privileged && getuid () != 0 && opt_userns_fd == -1)
@@ -2502,7 +2507,7 @@
         die_with_error ("Setting userns2 failed");
 
       /* We don't need any privileges in the launcher, drop them immediately. */
-      drop_privs (FALSE);
+      drop_privs (FALSE, FALSE);
 
       /* Optionally bind our lifecycle to that of the parent */
       handle_die_with_parent ();
@@ -2677,7 +2682,7 @@
       if (child == 0)
         {
           /* Unprivileged setup process */
-          drop_privs (FALSE);
+          drop_privs (FALSE, TRUE);
           close (privsep_sockets[0]);
           setup_newroot (opt_unshare_pid, privsep_sockets[1]);
           exit (0);
@@ -2775,7 +2780,7 @@
     }
 
   /* All privileged ops are done now, so drop caps we don't need */
-  drop_privs (!is_privileged);
+  drop_privs (!is_privileged, TRUE);
 
   if (opt_block_fd != -1)
     {
```
