# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3888_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3888_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 6158-6199 of the vulnerable file.

            // read-buffer and fetch more data as necessary.
            return 0;
        }

        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return -1;
        }

        c->cmd = c->binary_header.request.opcode;
        c->keylen = c->binary_header.request.keylen;
        c->opaque = c->binary_header.request.opaque;
        /* clear the returned cas value */
        c->cas = 0;

        c->last_cmd_time = current_time;
        // sigh. binprot has no "largest possible extlen" define, and I don't
        // want to refactor a ton of code either. Header is only ever used out
        // of c->binary_header, but the extlen stuff is used for the latter
        // bytes. Just wastes 24 bytes on the stack this way.
        char extbuf[sizeof(c->binary_header) + BIN_MAX_EXTLEN];
        memcpy(extbuf + sizeof(c->binary_header), c->rcurr + sizeof(c->binary_header), extlen);
        c->rbytes -= sizeof(c->binary_header) + extlen + keylen;
        c->rcurr += sizeof(c->binary_header) + extlen + keylen;

        dispatch_bin_command(c, extbuf);
    }

    return 1;
}

static int try_read_command_asciiauth(conn *c) {
    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    char *cont = NULL;

    if (!c->resp) {
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return 1;
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6175,8 +6175,9 @@
         // want to refactor a ton of code either. Header is only ever used out
         // of c->binary_header, but the extlen stuff is used for the latter
         // bytes. Just wastes 24 bytes on the stack this way.
-        char extbuf[sizeof(c->binary_header) + BIN_MAX_EXTLEN];
-        memcpy(extbuf + sizeof(c->binary_header), c->rcurr + sizeof(c->binary_header), extlen);
+        char extbuf[sizeof(c->binary_header) + BIN_MAX_EXTLEN+1];
+        memcpy(extbuf + sizeof(c->binary_header), c->rcurr + sizeof(c->binary_header),
+                extlen > BIN_MAX_EXTLEN ? BIN_MAX_EXTLEN : extlen);
         c->rbytes -= sizeof(c->binary_header) + extlen + keylen;
         c->rcurr += sizeof(c->binary_header) + extlen + keylen;
 
```
