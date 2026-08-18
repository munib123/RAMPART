# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1906_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1906_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 1445-1502 of the vulnerable file.


  if (context->sockets & FLATPAK_CONTEXT_SOCKET_PULSEAUDIO)
    {
      g_debug ("Allowing pulseaudio access");
      flatpak_run_add_pulseaudio_args (bwrap);
    }

  if (context->sockets & FLATPAK_CONTEXT_SOCKET_PCSC)
    {
      flatpak_run_add_pcsc_args (bwrap);
    }

  if (context->sockets & FLATPAK_CONTEXT_SOCKET_CUPS)
    {
      flatpak_run_add_cups_args (bwrap);
    }

  flatpak_run_add_session_dbus_args (bwrap, proxy_arg_bwrap, context, flags, app_id);
  flatpak_run_add_system_dbus_args (bwrap, proxy_arg_bwrap, context, flags);
  flatpak_run_add_a11y_dbus_args (bwrap, proxy_arg_bwrap, context, flags);

  if (g_environ_getenv (bwrap->envp, "LD_LIBRARY_PATH") != NULL)
    {
      /* LD_LIBRARY_PATH is overridden for setuid helper, so pass it as cmdline arg */
      flatpak_bwrap_add_args (bwrap,
                              "--setenv", "LD_LIBRARY_PATH", g_environ_getenv (bwrap->envp, "LD_LIBRARY_PATH"),
                              NULL);
      flatpak_bwrap_unset_env (bwrap, "LD_LIBRARY_PATH");
    }

  if (g_environ_getenv (bwrap->envp, "TMPDIR") != NULL)
    {
      /* TMPDIR is overridden for setuid helper, so pass it as cmdline arg */
      flatpak_bwrap_add_args (bwrap,
                              "--setenv", "TMPDIR", g_environ_getenv (bwrap->envp, "TMPDIR"),
                              NULL);
      flatpak_bwrap_unset_env (bwrap, "TMPDIR");
    }

  /* Must run this before spawning the dbus proxy, to ensure it
     ends up in the app cgroup */
  if (!flatpak_run_in_transient_unit (app_id, &my_error))
    {
      /* We still run along even if we don't get a cgroup, as nothing
         really depends on it. Its just nice to have */
      g_debug ("Failed to run in transient scope: %s", my_error->message);
      g_clear_error (&my_error);
    }

  if (!flatpak_bwrap_is_empty (proxy_arg_bwrap) &&
      !start_dbus_proxy (bwrap, proxy_arg_bwrap, app_info_path, error))
    return FALSE;

  if (exports_out)
    *exports_out = g_steal_pointer (&exports);

  return TRUE;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1462,24 +1462,6 @@
   flatpak_run_add_session_dbus_args (bwrap, proxy_arg_bwrap, context, flags, app_id);
   flatpak_run_add_system_dbus_args (bwrap, proxy_arg_bwrap, context, flags);
   flatpak_run_add_a11y_dbus_args (bwrap, proxy_arg_bwrap, context, flags);
-
-  if (g_environ_getenv (bwrap->envp, "LD_LIBRARY_PATH") != NULL)
-    {
-      /* LD_LIBRARY_PATH is overridden for setuid helper, so pass it as cmdline arg */
-      flatpak_bwrap_add_args (bwrap,
-                              "--setenv", "LD_LIBRARY_PATH", g_environ_getenv (bwrap->envp, "LD_LIBRARY_PATH"),
-                              NULL);
-      flatpak_bwrap_unset_env (bwrap, "LD_LIBRARY_PATH");
-    }
-
-  if (g_environ_getenv (bwrap->envp, "TMPDIR") != NULL)
-    {
-      /* TMPDIR is overridden for setuid helper, so pass it as cmdline arg */
-      flatpak_bwrap_add_args (bwrap,
-                              "--setenv", "TMPDIR", g_environ_getenv (bwrap->envp, "TMPDIR"),
-                              NULL);
-      flatpak_bwrap_unset_env (bwrap, "TMPDIR");
-    }
 
   /* Must run this before spawning the dbus proxy, to ensure it
      ends up in the app cgroup */
@@ -4068,6 +4050,8 @@
       command = default_command;
     }
 
+  flatpak_bwrap_envp_to_args (bwrap);
+
   if (!flatpak_bwrap_bundle_args (bwrap, 1, -1, FALSE, error))
     return FALSE;
 
@@ -4097,6 +4081,12 @@
 
       /* We use LEAVE_DESCRIPTORS_OPEN to work around dead-lock, see flatpak_close_fds_workaround */
       spawn_flags |= G_SPAWN_LEAVE_DESCRIPTORS_OPEN;
+
+      /* flatpak_bwrap_envp_to_args() moved the environment variables to
+       * be set into --setenv instructions in argv, so the environment
+       * in which the bwrap command runs must be empty. */
+      g_assert (bwrap->envp != NULL);
+      g_assert (bwrap->envp[0] == NULL);
 
       if (!g_spawn_async (NULL,
                           (char **) bwrap->argv->pdata,
@@ -4125,6 +4115,12 @@
        * we do want to allow inheriting fds into flatpak run. */
       flatpak_bwrap_child_setup (bwrap->fds, FALSE);
 
+      /* flatpak_bwrap_envp_to_args() moved the environment variables to
+       * be set into --setenv instructions in argv, so the environment
+       * in which the bwrap command runs must be empty. */
+      g_assert (bwrap->envp != NULL);
+      g_assert (bwrap->envp[0] == NULL);
+
       if (execvpe (flatpak_get_bwrap (), (char **) bwrap->argv->pdata, bwrap->envp) == -1)
         {
           g_set_error_literal (error, G_IO_ERROR, g_io_error_from_errno (errno),
```
