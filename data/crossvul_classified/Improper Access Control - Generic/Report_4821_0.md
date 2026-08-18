# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4821_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4821_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 294-334 of the vulnerable file.


        if (getpid() == 1 && (st.st_mode & 0044) != 0044)
                log_warning("Configuration file %s is marked world-inaccessible. This has no effect as configuration data is accessible via APIs without restrictions. Proceeding anyway.", path);

        return 0;
}

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode) {
        _cleanup_close_ int fd;
        int r;

        assert(path);

        if (parents)
                mkdir_parents(path, 0755);

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, mode > 0 ? mode : 0644);
        if (fd < 0)
                return -errno;

        if (mode > 0) {
                r = fchmod(fd, mode);
                if (r < 0)
                        return -errno;
        }

        if (uid != UID_INVALID || gid != GID_INVALID) {
                r = fchown(fd, uid, gid);
                if (r < 0)
                        return -errno;
        }

        if (stamp != USEC_INFINITY) {
                struct timespec ts[2];

                timespec_store(&ts[0], stamp);
                ts[1] = ts[0];
                r = futimens(fd, ts);
        } else
                r = futimens(fd, NULL);
        if (r < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -311,7 +311,7 @@
         if (fd < 0)
                 return -errno;
 
-        if (mode > 0) {
+        if (mode != MODE_INVALID) {
                 r = fchmod(fd, mode);
                 if (r < 0)
                         return -errno;
@@ -338,7 +338,7 @@
 }
 
 int touch(const char *path) {
-        return touch_file(path, false, USEC_INFINITY, UID_INVALID, GID_INVALID, 0);
+        return touch_file(path, false, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
 }
 
 int symlink_idempotent(const char *from, const char *to) {
```
