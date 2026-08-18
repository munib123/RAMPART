# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1909_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1909_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 981-1021 of the vulnerable file.

          int from_fd = fd_map[j].from;
          if (from_fd == to_fd)
            {
              conflict = TRUE;
              break;
            }
        }

      if (conflict)
        fd_map[i].to = ++max_fd;
    }

  if (arg_flags & FLATPAK_SPAWN_FLAGS_CLEAR_ENV)
    {
      char *empty[] = { NULL };
      env = g_strdupv (empty);
    }
  else
    env = g_get_environ ();

  n_envs = g_variant_n_children (arg_envs);
  for (i = 0; i < n_envs; i++)
    {
      const char *var = NULL;
      const char *val = NULL;
      g_variant_get_child (arg_envs, i, "{&s&s}", &var, &val);

      env = g_environ_setenv (env, var, val, TRUE);
    }

  g_ptr_array_add (flatpak_argv, g_strdup ("flatpak"));
  g_ptr_array_add (flatpak_argv, g_strdup ("run"));

  sandboxed = (arg_flags & FLATPAK_SPAWN_FLAGS_SANDBOX) != 0;

  if (sandboxed)
    {
      g_ptr_array_add (flatpak_argv, g_strdup ("--sandbox"));

      if (sandbox_flags & FLATPAK_SPAWN_SANDBOX_FLAGS_SHARE_DISPLAY)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -998,6 +998,13 @@
   else
     env = g_get_environ ();
 
+  /* Let the environment variables given by the caller override the ones
+   * from extra_args. Don't add them to @env, because they are controlled
+   * by our caller, which might be trying to use them to inject code into
+   * flatpak(1); add them to the environment block instead.
+   *
+   * We don't use --env= here, so that if the values are something that
+   * should not be exposed to other uids, they can remain confidential. */
   n_envs = g_variant_n_children (arg_envs);
   for (i = 0; i < n_envs; i++)
     {
@@ -1005,7 +1012,26 @@
       const char *val = NULL;
       g_variant_get_child (arg_envs, i, "{&s&s}", &var, &val);
 
-      env = g_environ_setenv (env, var, val, TRUE);
+      if (var[0] == '\0')
+        {
+          g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
+                                                 G_DBUS_ERROR_INVALID_ARGS,
+                                                 "Environment variable cannot have empty name");
+          return G_DBUS_METHOD_INVOCATION_HANDLED;
+        }
+
+      if (strchr (var, '=') != NULL)
+        {
+          g_dbus_method_invocation_return_error (invocation, G_DBUS_ERROR,
+                                                 G_DBUS_ERROR_INVALID_ARGS,
+                                                 "Environment variable name cannot contain '='");
+          return G_DBUS_METHOD_INVOCATION_HANDLED;
+        }
+
+      g_string_append (env_string, var);
+      g_string_append_c (env_string, '=');
+      g_string_append (env_string, val);
+      g_string_append_c (env_string, '\0');
     }
 
   g_ptr_array_add (flatpak_argv, g_strdup ("flatpak"));
```
