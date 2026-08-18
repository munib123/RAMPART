# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4700_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4700_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3131-3171 of the vulnerable file.

            c->rcurr += sizeof(c->binary_header);
        }
    } else {
        char *el, *cont;

        if (c->rbytes == 0)
            return 0;

        el = memchr(c->rcurr, '\n', c->rbytes);
        if (!el) {
            if (c->rbytes > 1024) {
                /*
                 * We didn't have a '\n' in the first k. This _has_ to be a
                 * large multiget, if not we should just nuke the connection.
                 */
                char *ptr = c->rcurr;
                while (*ptr == ' ') { /* ignore leading whitespaces */
                    ++ptr;
                }

                if (strcmp(ptr, "get ") && strcmp(ptr, "gets ")) {
                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }

            return 0;
        }
        cont = el + 1;
        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
            el--;
        }
        *el = '\0';

        assert(cont <= (c->rcurr + c->rbytes));

        process_command(c, c->rcurr);

        c->rbytes -= (cont - c->rcurr);
        c->rcurr = cont;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3148,7 +3148,9 @@
                     ++ptr;
                 }
 
-                if (strcmp(ptr, "get ") && strcmp(ptr, "gets ")) {
+                if (ptr - c->rcurr > 100 ||
+                    (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {
+
                     conn_set_state(c, conn_closing);
                     return 1;
                 }
```
