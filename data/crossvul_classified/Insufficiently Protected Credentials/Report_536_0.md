# CrossVul Fix Pair: Credentials Management Errors in c
**Pair ID:** 536_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `536_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```c
Lines 1232-1272 of the vulnerable file.

                else
                        cached_underline_enabled = false;
        }

        return cached_underline_enabled;
}

int vt_default_utf8(void) {
        _cleanup_free_ char *b = NULL;
        int r;

        /* Read the default VT UTF8 setting from the kernel */

        r = read_one_line_file("/sys/module/vt/parameters/default_utf8", &b);
        if (r < 0)
                return r;

        return parse_boolean(b);
}

int vt_reset_keyboard(int fd) {
        int kb;

        /* If we can't read the default, then default to unicode. It's 2017 after all. */
        kb = vt_default_utf8() != 0 ? K_UNICODE : K_XLATE;

        if (ioctl(fd, KDSKBMODE, kb) < 0)
                return -errno;

        return 0;
}

int vt_restore(int fd) {
        static const struct vt_mode mode = {
                .mode = VT_AUTO,
        };
        int r, q = 0;

        r = ioctl(fd, KDSETMODE, KD_TEXT);
        if (r < 0)
                q = log_debug_errno(errno, "Failed to set VT in text mode, ignoring: %m");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1249,11 +1249,35 @@
         return parse_boolean(b);
 }
 
+int vt_verify_kbmode(int fd) {
+        int curr_mode;
+
+        /*
+         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
+         * Otherwise we would (likely) interfere with X11's processing of the
+         * key events.
+         *
+         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
+         */
+
+        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
+                return -errno;
+
+        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
+}
+
 int vt_reset_keyboard(int fd) {
-        int kb;
+        int kb, r;
 
         /* If we can't read the default, then default to unicode. It's 2017 after all. */
         kb = vt_default_utf8() != 0 ? K_UNICODE : K_XLATE;
+
+        r = vt_verify_kbmode(fd);
+        if (r == -EBUSY) {
+                log_debug_errno(r, "Keyboard is not in XLATE or UNICODE mode, not resetting: %m");
+                return 0;
+        } else if (r < 0)
+                return r;
 
         if (ioctl(fd, KDSKBMODE, kb) < 0)
                 return -errno;
```
