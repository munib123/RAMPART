# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1906_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1906_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 90-130 of the vulnerable file.

void
flatpak_bwrap_set_env (FlatpakBwrap *bwrap,
                       const char   *variable,
                       const char   *value,
                       gboolean      overwrite)
{
  bwrap->envp = g_environ_setenv (bwrap->envp, variable, value, overwrite);
}

void
flatpak_bwrap_unset_env (FlatpakBwrap *bwrap,
                         const char   *variable)
{
  bwrap->envp = g_environ_unsetenv (bwrap->envp, variable);
}

void
flatpak_bwrap_add_arg (FlatpakBwrap *bwrap, const char *arg)
{
  g_ptr_array_add (bwrap->argv, g_strdup (arg));
}

void
flatpak_bwrap_finish (FlatpakBwrap *bwrap)
{
  g_ptr_array_add (bwrap->argv, NULL);
}

void
flatpak_bwrap_add_noinherit_fd (FlatpakBwrap *bwrap,
                                int           fd)
{
  g_array_append_val (bwrap->noinherit_fds, fd);
}

void
flatpak_bwrap_add_fd (FlatpakBwrap *bwrap,
                      int           fd)
{
  g_array_append_val (bwrap->fds, fd);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,6 +109,18 @@
   g_ptr_array_add (bwrap->argv, g_strdup (arg));
 }
 
+/*
+ * flatpak_bwrap_take_arg:
+ * @arg: (transfer full): Take ownership of this argument
+ *
+ * Add @arg to @bwrap's argv, taking ownership of the pointer.
+ */
+void
+flatpak_bwrap_take_arg (FlatpakBwrap *bwrap, char *arg)
+{
+  g_ptr_array_add (bwrap->argv, arg);
+}
+
 void
 flatpak_bwrap_finish (FlatpakBwrap *bwrap)
 {
@@ -274,6 +286,37 @@
     }
 }
 
+/*
+ * Convert bwrap->envp into a series of --setenv arguments for bwrap(1),
+ * assumed to be applied to an empty environment. Reset envp to be an
+ * empty environment.
+ */
+void
+flatpak_bwrap_envp_to_args (FlatpakBwrap *bwrap)
+{
+  gsize i;
+
+  for (i = 0; bwrap->envp[i] != NULL; i++)
+    {
+      char *key_val = bwrap->envp[i];
+      char *eq = strchr (key_val, '=');
+
+      if (eq)
+        {
+          flatpak_bwrap_add_arg (bwrap, "--setenv");
+          flatpak_bwrap_take_arg (bwrap, g_strndup (key_val, eq - key_val));
+          flatpak_bwrap_add_arg (bwrap, eq + 1);
+        }
+      else
+        {
+          g_warn_if_reached ();
+        }
+    }
+
+  g_strfreev (g_steal_pointer (&bwrap->envp));
+  bwrap->envp = g_strdupv (flatpak_bwrap_empty_env);
+}
+
 gboolean
 flatpak_bwrap_bundle_args (FlatpakBwrap *bwrap,
                            int           start,
```
