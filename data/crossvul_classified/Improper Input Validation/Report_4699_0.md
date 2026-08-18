# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4699_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4699_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3110-3150 of the vulnerable file.

                out_string(c, "SERVER_ERROR out of memory");
                return 0;
            }

            c->cmd = c->binary_header.request.opcode;
            c->keylen = c->binary_header.request.keylen;
            c->opaque = c->binary_header.request.opaque;
            /* clear the returned cas value */
            c->cas = 0;

            dispatch_bin_command(c);

            c->rbytes -= sizeof(c->binary_header);
            c->rcurr += sizeof(c->binary_header);
        }
    } else {
        char *el, *cont;

        if (c->rbytes == 0)
            return 0;
        el = memchr(c->rcurr, '\n', c->rbytes);
        if (!el)
            return 0;
        cont = el + 1;
        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
            el--;
        }
        *el = '\0';

        assert(cont <= (c->rcurr + c->rbytes));

        process_command(c, c->rcurr);

        c->rbytes -= (cont - c->rcurr);
        c->rcurr = cont;

        assert(c->rcurr <= (c->rbuf + c->rsize));
    }

    return 1;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3127,9 +3127,27 @@
 
         if (c->rbytes == 0)
             return 0;
+
         el = memchr(c->rcurr, '\n', c->rbytes);
-        if (!el)
+        if (!el) {
+            if (c->rbytes > 1024) {
+                /*
+                 * We didn't have a '\n' in the first k. This _has_ to be a
+                 * large multiget, if not we should just nuke the connection.
+                 */
+                char *ptr = c->rcurr;
+                while (*ptr == ' ') { /* ignore leading whitespaces */
+                    ++ptr;
+                }
+
+                if (strcmp(ptr, "get ") && strcmp(ptr, "gets ")) {
+                    conn_set_state(c, conn_closing);
+                    return 1;
+                }
+            }
+
             return 0;
+        }
         cont = el + 1;
         if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
             el--;
@@ -3191,12 +3209,17 @@
  * close.
  * before reading, move the remaining incomplete fragment of a command
  * (if any) to the beginning of the buffer.
+ *
+ * To protect us from someone flooding a connection with bogus data causing
+ * the connection to eat up all available memory, break out and start looking
+ * at the data I've got after a number of reallocs...
+ *
  * @return enum try_read_result
  */
 static enum try_read_result try_read_network(conn *c) {
     enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
     int res;
-
+    int num_allocs = 0;
     assert(c != NULL);
 
     if (c->rcurr != c->rbuf) {
@@ -3207,6 +3230,10 @@
 
     while (1) {
         if (c->rbytes >= c->rsize) {
+            if (num_allocs == 4) {
+                return gotdata;
+            }
+            ++num_allocs;
             char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
             if (!new_rbuf) {
                 if (settings.verbose > 0)
```
