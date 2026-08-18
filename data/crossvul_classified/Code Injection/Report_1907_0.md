# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1907_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1907_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 1103-1143 of the vulnerable file.

option_env_cb (const gchar *option_name,
               const gchar *value,
               gpointer     data,
               GError     **error)
{
  FlatpakContext *context = data;
  g_auto(GStrv) split = g_strsplit (value, "=", 2);

  if (split == NULL || split[0] == NULL || split[0][0] == 0 || split[1] == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                   _("Invalid env format %s"), value);
      return FALSE;
    }

  flatpak_context_set_env_var (context, split[0], split[1]);
  return TRUE;
}

static gboolean
option_own_name_cb (const gchar *option_name,
                    const gchar *value,
                    gpointer     data,
                    GError     **error)
{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_session_bus_policy (context, value, FLATPAK_POLICY_OWN);
  return TRUE;
}

static gboolean
option_talk_name_cb (const gchar *option_name,
                     const gchar *value,
                     gpointer     data,
                     GError     **error)
{
  FlatpakContext *context = data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1120,6 +1120,65 @@
 }
 
 static gboolean
+option_env_fd_cb (const gchar *option_name,
+                  const gchar *value,
+                  gpointer     data,
+                  GError     **error)
+{
+  FlatpakContext *context = data;
+  g_autoptr(GBytes) env_block = NULL;
+  gsize remaining;
+  const char *p;
+  guint64 fd;
+  gchar *endptr;
+
+  fd = g_ascii_strtoull (value, &endptr, 10);
+
+  if (endptr == NULL || *endptr != '\0' || fd > G_MAXINT)
+    return glnx_throw (error, "Not a valid file descriptor: %s", value);
+
+  env_block = glnx_fd_readall_bytes ((int) fd, NULL, error);
+
+  if (env_block == NULL)
+    return FALSE;
+
+  p = g_bytes_get_data (env_block, &remaining);
+
+  /* env_block might not be \0-terminated */
+  while (remaining > 0)
+    {
+      size_t len = strnlen (p, remaining);
+      const char *equals;
+
+      g_assert (len <= remaining);
+
+      equals = memchr (p, '=', len);
+
+      if (equals == NULL || equals == p)
+        return glnx_throw (error,
+                           "Environment variable must be given in the form VARIABLE=VALUE, not %.*s", (int) len, p);
+
+      flatpak_context_set_env_var (context,
+                                   g_strndup (p, equals - p),
+                                   g_strndup (equals + 1, len - (equals - p) - 1));
+      p += len;
+      remaining -= len;
+
+      if (remaining > 0)
+        {
+          g_assert (*p == '\0');
+          p += 1;
+          remaining -= 1;
+        }
+    }
+
+  if (fd >= 3)
+    close (fd);
+
+  return TRUE;
+}
+
+static gboolean
 option_own_name_cb (const gchar *option_name,
                     const gchar *value,
                     gpointer     data,
@@ -1316,6 +1375,7 @@
   { "filesystem", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_filesystem_cb, N_("Expose filesystem to app (:ro for read-only)"), N_("FILESYSTEM[:ro]") },
   { "nofilesystem", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_nofilesystem_cb, N_("Don't expose filesystem to app"), N_("FILESYSTEM") },
   { "env", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_env_cb, N_("Set environment variable"), N_("VAR=VALUE") },
+  { "env-fd", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_env_fd_cb, N_("Read environment variables in env -0 format from FD"), N_("FD") },
   { "own-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_own_name_cb, N_("Allow app to own name on the session bus"), N_("DBUS_NAME") },
   { "talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_talk_name_cb, N_("Allow app to talk to name on the session bus"), N_("DBUS_NAME") },
   { "no-talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_no_talk_name_cb, N_("Don't allow app to talk to name on the session bus"), N_("DBUS_NAME") },
```
