# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 1356_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1356_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 324-364 of the vulnerable file.

        p = strjoina("/dev/input/", b->name);

        b->fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (b->fd < 0)
                return log_warning_errno(errno, "Failed to open %s: %m", p);

        r = button_suitable(b);
        if (r < 0)
                return log_warning_errno(r, "Failed to determine whether input device is relevant to us: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                       "Device %s does not expose keys or switches relevant to us, ignoring.",
                                       p);

        if (ioctl(b->fd, EVIOCGNAME(sizeof(name)), name) < 0) {
                r = log_error_errno(errno, "Failed to get input name: %m");
                goto fail;
        }

        (void) button_set_mask(b);

        r = sd_event_add_io(b->manager->event, &b->io_event_source, b->fd, EPOLLIN, button_dispatch, b);
        if (r < 0) {
                log_error_errno(r, "Failed to add button event: %m");
                goto fail;
        }

        log_info("Watching system buttons on /dev/input/%s (%s)", b->name, name);

        return 0;

fail:
        b->fd = safe_close(b->fd);
        return r;
}

int button_check_switches(Button *b) {
        unsigned long switches[CONST_MAX(SW_LID, SW_DOCK)/ULONG_BITS+1] = {};
        assert(b);

        if (b->fd < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -341,7 +341,8 @@
         }
 
         (void) button_set_mask(b);
-
+        
+        b->io_event_source = sd_event_source_unref(b->io_event_source);
         r = sd_event_add_io(b->manager->event, &b->io_event_source, b->fd, EPOLLIN, button_dispatch, b);
         if (r < 0) {
                 log_error_errno(r, "Failed to add button event: %m");
```
