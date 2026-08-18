# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1906_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1906_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.

  GPtrArray *argv;
  GArray    *noinherit_fds; /* Just keep these open while the bwrap lives */
  GArray    *fds;
  GStrv      envp;
} FlatpakBwrap;

extern char *flatpak_bwrap_empty_env[1];

FlatpakBwrap *flatpak_bwrap_new (char **env);
void          flatpak_bwrap_free (FlatpakBwrap *bwrap);
void          flatpak_bwrap_set_env (FlatpakBwrap *bwrap,
                                     const char   *variable,
                                     const char   *value,
                                     gboolean      overwrite);
gboolean      flatpak_bwrap_is_empty (FlatpakBwrap *bwrap);
void          flatpak_bwrap_finish (FlatpakBwrap *bwrap);
void          flatpak_bwrap_unset_env (FlatpakBwrap *bwrap,
                                       const char   *variable);
void          flatpak_bwrap_add_arg (FlatpakBwrap *bwrap,
                                     const char   *arg);
void          flatpak_bwrap_add_noinherit_fd (FlatpakBwrap *bwrap,
                                              int           fd);
void          flatpak_bwrap_add_fd (FlatpakBwrap *bwrap,
                                    int           fd);
void          flatpak_bwrap_add_args (FlatpakBwrap *bwrap,
                                      ...) G_GNUC_NULL_TERMINATED;
void          flatpak_bwrap_add_arg_printf (FlatpakBwrap *bwrap,
                                            const char   *format,
                                            ...) G_GNUC_PRINTF (2, 3);
void          flatpak_bwrap_append_argsv (FlatpakBwrap *bwrap,
                                          char        **args,
                                          int           len);
void          flatpak_bwrap_append_bwrap (FlatpakBwrap *bwrap,
                                          FlatpakBwrap *other);       /* Steals the fds */
void          flatpak_bwrap_append_args (FlatpakBwrap *bwrap,
                                         GPtrArray    *other_array);
void          flatpak_bwrap_add_args_data_fd (FlatpakBwrap *bwrap,
                                              const char   *op,
                                              int           fd,
                                              const char   *path_optional);
gboolean      flatpak_bwrap_add_args_data (FlatpakBwrap *bwrap,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,8 @@
                                        const char   *variable);
 void          flatpak_bwrap_add_arg (FlatpakBwrap *bwrap,
                                      const char   *arg);
+void          flatpak_bwrap_take_arg (FlatpakBwrap *bwrap,
+                                      char         *arg);
 void          flatpak_bwrap_add_noinherit_fd (FlatpakBwrap *bwrap,
                                               int           fd);
 void          flatpak_bwrap_add_fd (FlatpakBwrap *bwrap,
@@ -73,6 +75,7 @@
                                           const char   *type,
                                           const char   *src,
                                           const char   *dest);
+void          flatpak_bwrap_envp_to_args (FlatpakBwrap *bwrap);
 gboolean      flatpak_bwrap_bundle_args (FlatpakBwrap *bwrap,
                                          int           start,
                                          int           end,
```
