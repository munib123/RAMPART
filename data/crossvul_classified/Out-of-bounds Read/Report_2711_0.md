# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2711_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2711_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1629-1669 of the vulnerable file.

        break;
    }
    tptr += stlv_len;
    len -= stlv_len;
  }
  return 0;

  trunc:
    ND_PRINT((ndo, "\n\t\t"));
    ND_PRINT((ndo, "%s", tstr));
    return(1);
}

/* shared routine for printing system, node and lsp-ids */
static char *
isis_print_id(const uint8_t *cp, int id_len)
{
    int i;
    static char id[sizeof("xxxx.xxxx.xxxx.yy-zz")];
    char *pos = id;

    for (i = 1; i <= SYSTEM_ID_LEN; i++) {
        snprintf(pos, sizeof(id) - (pos - id), "%02x", *cp++);
	pos += strlen(pos);
	if (i == 2 || i == 4)
	    *pos++ = '.';
	}
    if (id_len >= NODE_ID_LEN) {
        snprintf(pos, sizeof(id) - (pos - id), ".%02x", *cp++);
	pos += strlen(pos);
    }
    if (id_len == LSP_ID_LEN)
        snprintf(pos, sizeof(id) - (pos - id), "-%02x", *cp);
    return (id);
}

/* print the 4-byte metric block which is common found in the old-style TLVs */
static int
isis_print_metric_block(netdissect_options *ndo,
                        const struct isis_metric_block *isis_metric_block)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1646,8 +1646,12 @@
     int i;
     static char id[sizeof("xxxx.xxxx.xxxx.yy-zz")];
     char *pos = id;
-
-    for (i = 1; i <= SYSTEM_ID_LEN; i++) {
+    int sysid_len;
+
+    sysid_len = SYSTEM_ID_LEN;
+    if (sysid_len > id_len)
+        sysid_len = id_len;
+    for (i = 1; i <= sysid_len; i++) {
         snprintf(pos, sizeof(id) - (pos - id), "%02x", *cp++);
 	pos += strlen(pos);
 	if (i == 2 || i == 4)
```
