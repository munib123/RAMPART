# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2714_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2714_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 793-833 of the vulnerable file.

	return len;

trunc:
	ND_PRINT((ndo, "[|lcp]"));
	return 0;
}

/* ML-PPP*/
static const struct tok ppp_ml_flag_values[] = {
    { 0x80, "begin" },
    { 0x40, "end" },
    { 0, NULL }
};

static void
handle_mlppp(netdissect_options *ndo,
             const u_char *p, int length)
{
    if (!ndo->ndo_eflag)
        ND_PRINT((ndo, "MLPPP, "));

    ND_PRINT((ndo, "seq 0x%03x, Flags [%s], length %u",
           (EXTRACT_16BITS(p))&0x0fff, /* only support 12-Bit sequence space for now */
           bittok2str(ppp_ml_flag_values, "none", *p & 0xc0),
           length));
}

/* CHAP */
static void
handle_chap(netdissect_options *ndo,
            const u_char *p, int length)
{
	u_int code, len;
	int val_size, name_size, msg_size;
	const u_char *p0;
	int i;

	p0 = p;
	if (length < 1) {
		ND_PRINT((ndo, "[|chap]"));
		return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -810,6 +810,15 @@
 {
     if (!ndo->ndo_eflag)
         ND_PRINT((ndo, "MLPPP, "));
+
+    if (length < 2) {
+        ND_PRINT((ndo, "[|mlppp]"));
+        return;
+    }
+    if (!ND_TTEST_16BITS(p)) {
+        ND_PRINT((ndo, "[|mlppp]"));
+        return;
+    }
 
     ND_PRINT((ndo, "seq 0x%03x, Flags [%s], length %u",
            (EXTRACT_16BITS(p))&0x0fff, /* only support 12-Bit sequence space for now */
```
