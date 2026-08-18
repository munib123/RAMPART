# CrossVul Fix Pair: Credentials Management Errors in c
**Pair ID:** 536_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `536_2`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```c
Lines 53-109 of the vulnerable file.

static int verify_vc_allocation(unsigned idx) {
        char vcname[sizeof("/dev/vcs") + DECIMAL_STR_MAX(unsigned) - 2];

        xsprintf(vcname, "/dev/vcs%u", idx);

        if (access(vcname, F_OK) < 0)
                return -errno;

        return 0;
}

static int verify_vc_allocation_byfd(int fd) {
        struct vt_stat vcs = {};

        if (ioctl(fd, VT_GETSTATE, &vcs) < 0)
                return -errno;

        return verify_vc_allocation(vcs.v_active);
}

static int verify_vc_kbmode(int fd) {
        int curr_mode;

        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */

        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
                return -errno;

        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
}

static int toggle_utf8(const char *name, int fd, bool utf8) {
        int r;
        struct termios tc = {};

        assert(name);

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode on %s: %m", enable_disable(utf8), name);

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", 3, false);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s UTF-8 term processing on %s: %m", enable_disable(utf8), name);

        r = tcgetattr(fd, &tc);
        if (r >= 0) {
                SET_FLAG(tc.c_iflag, IUTF8, utf8);
                r = tcsetattr(fd, TCSANOW, &tc);
        }
        if (r < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,28 +70,18 @@
         return verify_vc_allocation(vcs.v_active);
 }
 
-static int verify_vc_kbmode(int fd) {
-        int curr_mode;
-
-        /*
-         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
-         * Otherwise we would (likely) interfere with X11's processing of the
-         * key events.
-         *
-         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
-         */
-
-        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
-                return -errno;
-
-        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
-}
-
 static int toggle_utf8(const char *name, int fd, bool utf8) {
         int r;
         struct termios tc = {};
 
         assert(name);
+
+        r = vt_verify_kbmode(fd);
+        if (r == -EBUSY) {
+                log_warning_errno(r, "Virtual console %s is not in K_XLATE or K_UNICODE: %m", name);
+                return 0;
+        } else if (r < 0)
+                return log_warning_errno(r, "Failed to verify kbdmode on %s: %m", name);
 
         r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
         if (r < 0)
@@ -290,7 +280,7 @@
                         continue;
                 }
 
-                if (verify_vc_kbmode(fd_d) < 0)
+                if (vt_verify_kbmode(fd_d) < 0)
                         continue;
 
                 toggle_utf8(ttyname, fd_d, utf8);
@@ -365,7 +355,7 @@
                                 err = -fd;
                         continue;
                 }
-                r = verify_vc_kbmode(fd);
+                r = vt_verify_kbmode(fd);
                 if (r < 0) {
                         if (!err)
                                 err = -r;
@@ -398,7 +388,7 @@
         if (r < 0)
                 return log_error_errno(r, "Virtual console %s is not allocated: %m", src_vc);
 
-        r = verify_vc_kbmode(fd);
+        r = vt_verify_kbmode(fd);
         if (r < 0)
                 return log_error_errno(r, "Virtual console %s is not in K_XLATE or K_UNICODE: %m", src_vc);
 
```
