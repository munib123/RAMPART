# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1011_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1011_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3446-3486 of the vulnerable file.

        } else if (nz_strcmp(nkey, stat_type, "sizes_enable") == 0) {
            item_stats_sizes_enable(add_stats, c);
        } else if (nz_strcmp(nkey, stat_type, "sizes_disable") == 0) {
            item_stats_sizes_disable(add_stats, c);
        } else {
            ret = false;
        }
    } else {
        ret = false;
    }

    return ret;
}

static inline void get_conn_text(const conn *c, const int af,
                char* addr, struct sockaddr *sock_addr) {
    char addr_text[MAXPATHLEN];
    addr_text[0] = '\0';
    const char *protoname = "?";
    unsigned short port = 0;

    switch (af) {
        case AF_INET:
            (void) inet_ntop(af,
                    &((struct sockaddr_in *)sock_addr)->sin_addr,
                    addr_text,
                    sizeof(addr_text) - 1);
            port = ntohs(((struct sockaddr_in *)sock_addr)->sin_port);
            protoname = IS_UDP(c->transport) ? "udp" : "tcp";
            break;

        case AF_INET6:
            addr_text[0] = '[';
            addr_text[1] = '\0';
            if (inet_ntop(af,
                    &((struct sockaddr_in6 *)sock_addr)->sin6_addr,
                    addr_text + 1,
                    sizeof(addr_text) - 2)) {
                strcat(addr_text, "]");
            }
            port = ntohs(((struct sockaddr_in6 *)sock_addr)->sin6_port);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3463,6 +3463,7 @@
     addr_text[0] = '\0';
     const char *protoname = "?";
     unsigned short port = 0;
+    size_t pathlen = 0;
 
     switch (af) {
         case AF_INET:
@@ -3488,10 +3489,27 @@
             break;
 
         case AF_UNIX:
+            // this strncpy call originally could piss off an address
+            // sanitizer; we supplied the size of the dest buf as a limiter,
+            // but optimized versions of strncpy could read past the end of
+            // *src while looking for a null terminator. Since buf and
+            // sun_path here are both on the stack they could even overlap,
+            // which is "undefined". In all OSS versions of strncpy I could
+            // find this has no effect; it'll still only copy until the first null
+            // terminator is found. Thus it's possible to get the OS to
+            // examine past the end of sun_path but it's unclear to me if this
+            // can cause any actual problem.
+            //
+            // We need a safe_strncpy util function but I'll punt on figuring
+            // that out for now.
+            pathlen = sizeof(((struct sockaddr_un *)sock_addr)->sun_path);
+            if (MAXPATHLEN <= pathlen) {
+                pathlen = MAXPATHLEN - 1;
+            }
             strncpy(addr_text,
                     ((struct sockaddr_un *)sock_addr)->sun_path,
-                    sizeof(addr_text) - 1);
-            addr_text[sizeof(addr_text)-1] = '\0';
+                    pathlen);
+            addr_text[pathlen] = '\0';
             protoname = "unix";
             break;
     }
```
