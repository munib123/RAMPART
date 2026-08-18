# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2651_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2651_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.

    Z_PACKET_CLIENTACK,
    Z_PACKET_STAT
};

static const struct tok z_types[] = {
    { Z_PACKET_UNSAFE,		"unsafe" },
    { Z_PACKET_UNACKED,		"unacked" },
    { Z_PACKET_ACKED,		"acked" },
    { Z_PACKET_HMACK,		"hm-ack" },
    { Z_PACKET_HMCTL,		"hm-ctl" },
    { Z_PACKET_SERVACK,		"serv-ack" },
    { Z_PACKET_SERVNAK,		"serv-nak" },
    { Z_PACKET_CLIENTACK,	"client-ack" },
    { Z_PACKET_STAT,		"stat" },
    { 0,			NULL }
};

static char z_buf[256];

static const char *
parse_field(netdissect_options *ndo, const char **pptr, int *len)
{
    const char *s;

    if (*len <= 0 || !pptr || !*pptr)
	return NULL;
    if (*pptr > (const char *) ndo->ndo_snapend)
	return NULL;

    s = *pptr;
    while (*pptr <= (const char *) ndo->ndo_snapend && *len >= 0 && **pptr) {
	(*pptr)++;
	(*len)--;
    }
    (*pptr)++;
    (*len)--;
    if (*len < 0 || *pptr > (const char *) ndo->ndo_snapend)
	return NULL;
    return s;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,24 +83,34 @@
 static char z_buf[256];
 
 static const char *
-parse_field(netdissect_options *ndo, const char **pptr, int *len)
+parse_field(netdissect_options *ndo, const char **pptr, int *len, int *truncated)
 {
     const char *s;
 
-    if (*len <= 0 || !pptr || !*pptr)
-	return NULL;
-    if (*pptr > (const char *) ndo->ndo_snapend)
-	return NULL;
-
+    /* Start of string */
     s = *pptr;
-    while (*pptr <= (const char *) ndo->ndo_snapend && *len >= 0 && **pptr) {
+    /* Scan for the NUL terminator */
+    for (;;) {
+	if (*len == 0) {
+	    /* Ran out of packet data without finding it */
+	    return NULL;
+	}
+	if (!ND_TTEST(**pptr)) {
+	    /* Ran out of captured data without finding it */
+	    *truncated = 1;
+	    return NULL;
+	}
+	if (**pptr == '\0') {
+	    /* Found it */
+	    break;
+	}
+	/* Keep scanning */
 	(*pptr)++;
 	(*len)--;
     }
+    /* Skip the NUL terminator */
     (*pptr)++;
     (*len)--;
-    if (*len < 0 || *pptr > (const char *) ndo->ndo_snapend)
-	return NULL;
     return s;
 }
 
@@ -139,6 +149,7 @@
     int parselen = length;
     const char *s;
     int lose = 0;
+    int truncated = 0;
 
     /* squelch compiler warnings */
 
@@ -149,8 +160,9 @@
     z.sender = 0;
     z.recipient = 0;
 
-#define PARSE_STRING				\
-	s = parse_field(ndo, &parse, &parselen);	\
+#define PARSE_STRING						\
+	s = parse_field(ndo, &parse, &parselen, &truncated);	\
+	if (truncated) goto trunc;				\
 	if (!s) lose = 1;
 
 #define PARSE_FIELD_INT(field)			\
@@ -183,10 +195,8 @@
     PARSE_FIELD_INT(z.multi);
     PARSE_FIELD_STR(z.multi_uid);
 
-    if (lose) {
-	ND_PRINT((ndo, " [|zephyr] (%d)", length));
-	return;
-    }
+    if (lose)
+        goto trunc;
 
     ND_PRINT((ndo, " zephyr"));
     if (strncmp(z.version+4, "0.2", 3)) {
@@ -318,4 +328,9 @@
     ND_PRINT((ndo, " to %s", z_triple(z.class, z.inst, z.recipient)));
     if (*z.opcode)
 	ND_PRINT((ndo, " op %s", z.opcode));
+    return;
+
+trunc:
+    ND_PRINT((ndo, " [|zephyr] (%d)", length));
+    return;
 }
```
