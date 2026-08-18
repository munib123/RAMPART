# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1455_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1455_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 313-353 of the vulnerable file.

    if (fd <= 2)
      uv__nonblock(fd, 0);

    if (close_fd != -1)
      uv__close(close_fd);
  }

  for (fd = 0; fd < stdio_count; fd++) {
    use_fd = pipes[fd][1];

    if (use_fd >= 0 && fd != use_fd)
      close(use_fd);
  }

  if (options->cwd != NULL && chdir(options->cwd)) {
    uv__write_int(error_fd, -errno);
    perror("chdir()");
    _exit(127);
  }

  if ((options->flags & UV_PROCESS_SETGID) && setgid(options->gid)) {
    uv__write_int(error_fd, -errno);
    perror("setgid()");
    _exit(127);
  }

  if ((options->flags & UV_PROCESS_SETUID) && setuid(options->uid)) {
    uv__write_int(error_fd, -errno);
    perror("setuid()");
    _exit(127);
  }

  if (options->env != NULL) {
    environ = options->env;
  }

  execvp(options->file, options->args);
  uv__write_int(error_fd, -errno);
  perror("execvp()");
  _exit(127);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,6 +328,17 @@
     uv__write_int(error_fd, -errno);
     perror("chdir()");
     _exit(127);
+  }
+
+  if (options->flags & (UV_PROCESS_SETUID | UV_PROCESS_SETGID)) {
+    /* When dropping privileges from root, the `setgroups` call will
+     * remove any extraneous groups. If we don't call this, then
+     * even though our uid has dropped, we may still have groups
+     * that enable us to do super-user things. This will fail if we
+     * aren't root, so don't bother checking the return value, this
+     * is just done as an optimistic privilege dropping function.
+     */
+    SAVE_ERRNO(setgroups(0, NULL));
   }
 
   if ((options->flags & UV_PROCESS_SETGID) && setgid(options->gid)) {
```
