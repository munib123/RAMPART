# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2648_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2648_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 59-99 of the vulnerable file.

    Z_PACKET_UNSAFE = 0,
    Z_PACKET_UNACKED,
    Z_PACKET_ACKED,
    Z_PACKET_HMACK,
    Z_PACKET_HMCTL,
    Z_PACKET_SERVACK,
    Z_PACKET_SERVNAK,
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
    { Z_PACKET_STAT,		"stat" }
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,8 @@
     { Z_PACKET_SERVACK,		"serv-ack" },
     { Z_PACKET_SERVNAK,		"serv-nak" },
     { Z_PACKET_CLIENTACK,	"client-ack" },
-    { Z_PACKET_STAT,		"stat" }
+    { Z_PACKET_STAT,		"stat" },
+    { 0,			NULL }
 };
 
 static char z_buf[256];
```
