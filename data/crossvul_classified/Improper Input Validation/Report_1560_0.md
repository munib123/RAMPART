# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1560_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1560_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 184-224 of the vulnerable file.

	char c;
	int nid;

	ND_PRINT((ndo, " wb-id:"));
	if (len < sizeof(*id) || !ND_TTEST(*id))
		return (-1);
	len -= sizeof(*id);

	ND_PRINT((ndo, " %u/%s:%u (max %u/%s:%u) ",
	       EXTRACT_32BITS(&id->pi_ps.slot),
	       ipaddr_string(ndo, &id->pi_ps.page.p_sid),
	       EXTRACT_32BITS(&id->pi_ps.page.p_uid),
	       EXTRACT_32BITS(&id->pi_mslot),
	       ipaddr_string(ndo, &id->pi_mpage.p_sid),
	       EXTRACT_32BITS(&id->pi_mpage.p_uid)));

	nid = EXTRACT_16BITS(&id->pi_ps.nid);
	len -= sizeof(*io) * nid;
	io = (struct id_off *)(id + 1);
	cp = (char *)(io + nid);
	if (!ND_TTEST2(cp, len)) {
		ND_PRINT((ndo, "\""));
		fn_print(ndo, (u_char *)cp, (u_char *)cp + len);
		ND_PRINT((ndo, "\""));
	}

	c = '<';
	for (i = 0; i < nid && ND_TTEST(*io); ++io, ++i) {
		ND_PRINT((ndo, "%c%s:%u",
		    c, ipaddr_string(ndo, &io->id), EXTRACT_32BITS(&io->off)));
		c = ',';
	}
	if (i >= nid) {
		ND_PRINT((ndo, ">"));
		return (0);
	}
	return (-1);
}

static int
wb_rreq(netdissect_options *ndo,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,7 +201,7 @@
 	len -= sizeof(*io) * nid;
 	io = (struct id_off *)(id + 1);
 	cp = (char *)(io + nid);
-	if (!ND_TTEST2(cp, len)) {
+	if (ND_TTEST2(cp, len)) {
 		ND_PRINT((ndo, "\""));
 		fn_print(ndo, (u_char *)cp, (u_char *)cp + len);
 		ND_PRINT((ndo, "\""));
@@ -266,7 +266,7 @@
 	}
 	n = EXTRACT_32BITS(&prep->pp_n);
 	ps = (const struct pgstate *)(prep + 1);
-	while (--n >= 0 && !ND_TTEST(*ps)) {
+	while (--n >= 0 && ND_TTEST(*ps)) {
 		const struct id_off *io, *ie;
 		char c = '<';
 
@@ -275,7 +275,7 @@
 		    ipaddr_string(ndo, &ps->page.p_sid),
 		    EXTRACT_32BITS(&ps->page.p_uid)));
 		io = (struct id_off *)(ps + 1);
-		for (ie = io + ps->nid; io < ie && !ND_TTEST(*io); ++io) {
+		for (ie = io + ps->nid; io < ie && ND_TTEST(*io); ++io) {
 			ND_PRINT((ndo, "%c%s:%u", c, ipaddr_string(ndo, &io->id),
 			    EXTRACT_32BITS(&io->off)));
 			c = ',';
```
