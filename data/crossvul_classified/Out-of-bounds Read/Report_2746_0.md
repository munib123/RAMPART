# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2746_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2746_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 29-76 of the vulnerable file.


#include "netdissect.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "extract.h"
#include "chdlc.h"

static void chdlc_slarp_print(netdissect_options *, const u_char *, u_int);

static const struct tok chdlc_cast_values[] = {
    { CHDLC_UNICAST, "unicast" },
    { CHDLC_BCAST, "bcast" },
    { 0, NULL}
};


/* Standard CHDLC printer */
u_int
chdlc_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)
{
	register u_int length = h->len;
	register u_int caplen = h->caplen;

	if (caplen < CHDLC_HDRLEN) {
		ND_PRINT((ndo, "[|chdlc]"));
		return (caplen);
	}
        return (chdlc_print(ndo, p,length));
}

u_int
chdlc_print(netdissect_options *ndo, register const u_char *p, u_int length)
{
	u_int proto;

	proto = EXTRACT_16BITS(&p[2]);
	if (ndo->ndo_eflag) {
                ND_PRINT((ndo, "%s, ethertype %s (0x%04x), length %u: ",
                       tok2str(chdlc_cast_values, "0x%02x", p[0]),
                       tok2str(ethertype_values, "Unknown", proto),
                       proto,
                       length));
	}

	length -= CHDLC_HDRLEN;
	p += CHDLC_HDRLEN;

	switch (proto) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,21 +46,18 @@
 u_int
 chdlc_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, register const u_char *p)
 {
-	register u_int length = h->len;
-	register u_int caplen = h->caplen;
-
-	if (caplen < CHDLC_HDRLEN) {
-		ND_PRINT((ndo, "[|chdlc]"));
-		return (caplen);
-	}
-        return (chdlc_print(ndo, p,length));
+	return chdlc_print(ndo, p, h->len);
 }
 
 u_int
 chdlc_print(netdissect_options *ndo, register const u_char *p, u_int length)
 {
 	u_int proto;
-
+	const u_char *bp = p;
+
+	if (length < CHDLC_HDRLEN)
+		goto trunc;
+	ND_TCHECK2(*p, CHDLC_HDRLEN);
 	proto = EXTRACT_16BITS(&p[2]);
 	if (ndo->ndo_eflag) {
                 ND_PRINT((ndo, "%s, ethertype %s (0x%04x), length %u: ",
@@ -94,6 +91,9 @@
 		break;
         case ETHERTYPE_ISO:
                 /* is the fudge byte set ? lets verify by spotting ISO headers */
+                if (length < 2)
+                    goto trunc;
+                ND_TCHECK_16BITS(p);
                 if (*(p+1) == 0x81 ||
                     *(p+1) == 0x82 ||
                     *(p+1) == 0x83)
@@ -108,6 +108,10 @@
 	}
 
 	return (CHDLC_HDRLEN);
+
+trunc:
+	ND_PRINT((ndo, "[|chdlc]"));
+	return ndo->ndo_snapend - bp;
 }
 
 /*
```
