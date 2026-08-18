# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 874_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `874_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2029-2069 of the vulnerable file.

    die_with_error ("Can't read /proc/sys/kernel/overflowuid");

  overflow_uid = strtol (uid_data, NULL, 10);
  if (overflow_uid == 0)
    die ("Can't parse /proc/sys/kernel/overflowuid");

  gid_data = load_file_at (AT_FDCWD, "/proc/sys/kernel/overflowgid");
  if (gid_data == NULL)
    die_with_error ("Can't read /proc/sys/kernel/overflowgid");

  overflow_gid = strtol (gid_data, NULL, 10);
  if (overflow_gid == 0)
    die ("Can't parse /proc/sys/kernel/overflowgid");
}

int
main (int    argc,
      char **argv)
{
  mode_t old_umask;
  cleanup_free char *base_path = NULL;
  int clone_flags;
  char *old_cwd = NULL;
  pid_t pid;
  int event_fd = -1;
  int child_wait_fd = -1;
  int setup_finished_pipe[] = {-1, -1};
  const char *new_cwd;
  uid_t ns_uid;
  gid_t ns_gid;
  struct stat sbuf;
  uint64_t val;
  int res UNUSED;
  cleanup_free char *seccomp_data = NULL;
  size_t seccomp_len;
  struct sock_fprog seccomp_prog;
  cleanup_free char *args_data = NULL;

  /* Handle --version early on before we try to acquire/drop
   * any capabilities so it works in a build environment;
   * right now flatpak's build runs bubblewrap --version.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2046,7 +2046,7 @@
       char **argv)
 {
   mode_t old_umask;
-  cleanup_free char *base_path = NULL;
+  const char *base_path = NULL;
   int clone_flags;
   char *old_cwd = NULL;
   pid_t pid;
@@ -2187,15 +2187,12 @@
     die_with_error ("Can't open /proc");
 
   /* We need *some* mountpoint where we can mount the root tmpfs.
-     We first try in /run, and if that fails, try in /tmp. */
-  base_path = xasprintf ("/run/user/%d/.bubblewrap", real_uid);
-  if (ensure_dir (base_path, 0755))
-    {
-      free (base_path);
-      base_path = xasprintf ("/tmp/.bubblewrap-%d", real_uid);
-      if (ensure_dir (base_path, 0755))
-        die_with_error ("Creating root mountpoint failed");
-    }
+   * Because we use pivot_root, it won't appear to be mounted from
+   * the perspective of the sandboxed process, so we can use anywhere
+   * that is sure to exist, that is sure to not be a symlink controlled
+   * by someone malicious, and that we won't immediately need to
+   * access ourselves. */
+  base_path = "/tmp";
 
   __debug__ (("creating new namespace\n"));
 
@@ -2400,7 +2397,8 @@
   /* We create a subdir "$base_path/newroot" for the new root, that
    * way we can pivot_root to base_path, and put the old root at
    * "$base_path/oldroot". This avoids problems accessing the oldroot
-   * dir if the user requested to bind mount something over / */
+   * dir if the user requested to bind mount something over / (or
+   * over /tmp, now that we use that for base_path). */
 
   if (mkdir ("newroot", 0755))
     die_with_error ("Creating newroot failed");
```
