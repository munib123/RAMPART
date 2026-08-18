# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1908_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1908_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 240-280 of the vulnerable file.

  g_hash_table_remove (client_pid_data_hash, GUINT_TO_POINTER (pid_data->pid));

  /* This might have caused us to go to idle (zero children) */
  schedule_idle_callback ();
}

typedef struct
{
  int from;
  int to;
  int final;
} FdMapEntry;

typedef struct
{
  FdMapEntry *fd_map;
  int         fd_map_len;
  int         instance_id_fd;
  gboolean    set_tty;
  int         tty;
} ChildSetupData;

typedef struct
{
  guint pid;
  gchar buffer[INSTANCE_ID_BUFFER_SIZE];
} InstanceIdReadData;

typedef struct
{
  FlatpakInstance *instance;
  guint            pid;
  guint            attempt;
} BwrapinfoWatcherData;

static void
bwrapinfo_watcher_data_free (BwrapinfoWatcherData* data)
{
  g_object_unref (data->instance);
  g_free (data);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -257,6 +257,7 @@
   int         instance_id_fd;
   gboolean    set_tty;
   int         tty;
+  int         env_fd;
 } ChildSetupData;
 
 typedef struct
@@ -484,6 +485,9 @@
 
   if (data->instance_id_fd != -1)
     drop_cloexec (data->instance_id_fd);
+
+  if (data->env_fd != -1)
+    drop_cloexec (data->env_fd);
 
   /* Unblock all signals */
   sigemptyset (&set);
@@ -782,8 +786,10 @@
   gboolean share_pids;
   gboolean notify_start;
   gboolean devel;
+  g_autoptr(GString) env_string = g_string_new ("");
 
   child_setup_data.instance_id_fd = -1;
+  child_setup_data.env_fd = -1;
 
   if (fd_list != NULL)
     fds = g_unix_fd_list_peek_fds (fd_list, &fds_len);
@@ -1044,7 +1050,49 @@
   else
     {
       for (i = 0; extra_args != NULL && extra_args[i] != NULL; i++)
-        g_ptr_array_add (flatpak_argv, g_strdup (extra_args[i]));
+        {
+          if (g_str_has_prefix (extra_args[i], "--env="))
+            {
+              const char *var_val = extra_args[i] + strlen ("--env=");
+
+              if (var_val[0] == '\0' || var_val[0] == '=')
+                {
+                  g_warning ("Environment variable in extra-args has empty name");
+                  continue;
+                }
+
+              if (strchr (var_val, '=') == NULL)
+                {
+                  g_warning ("Environment variable in extra-args has no value");
+                  continue;
+                }
+
+              g_string_append (env_string, var_val);
+              g_string_append_c (env_string, '\0');
+            }
+          else
+            {
+              g_ptr_array_add (flatpak_argv, g_strdup (extra_args[i]));
+            }
+        }
+    }
+
+  if (env_string->len > 0)
+    {
+      g_auto(GLnxTmpfile) env_tmpf  = { 0, };
+
+      if (!flatpak_buffer_to_sealed_memfd_or_tmpfile (&env_tmpf, "environ",
+                                                      env_string->str,
+                                                      env_string->len, &error))
+        {
+          g_dbus_method_invocation_return_gerror (invocation, error);
+          return G_DBUS_METHOD_INVOCATION_HANDLED;
+        }
+
+      child_setup_data.env_fd = glnx_steal_fd (&env_tmpf.fd);
+      g_ptr_array_add (flatpak_argv,
+                       g_strdup_printf ("--env-fd=%d",
+                                        child_setup_data.env_fd));
     }
 
   expose_pids = (arg_flags & FLATPAK_SPAWN_FLAGS_EXPOSE_PIDS) != 0;
```
