# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2689_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2689_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 246-286 of the vulnerable file.

	ND_PRINT((ndo, " wb-preq:"));
	if (len < sizeof(*preq) || !ND_TTEST(*preq))
		return (-1);

	ND_PRINT((ndo, " need %u/%s:%u",
	       EXTRACT_32BITS(&preq->pp_low),
	       ipaddr_string(ndo, &preq->pp_page.p_sid),
	       EXTRACT_32BITS(&preq->pp_page.p_uid)));
	return (0);
}

static int
wb_prep(netdissect_options *ndo,
        const struct pkt_prep *prep, u_int len)
{
	int n;
	const struct pgstate *ps;
	const u_char *ep = ndo->ndo_snapend;

	ND_PRINT((ndo, " wb-prep:"));
	if (len < sizeof(*prep)) {
		return (-1);
	}
	n = EXTRACT_32BITS(&prep->pp_n);
	ps = (const struct pgstate *)(prep + 1);
	while (--n >= 0 && ND_TTEST(*ps)) {
		const struct id_off *io, *ie;
		char c = '<';

		ND_PRINT((ndo, " %u/%s:%u",
		    EXTRACT_32BITS(&ps->slot),
		    ipaddr_string(ndo, &ps->page.p_sid),
		    EXTRACT_32BITS(&ps->page.p_uid)));
		io = (const struct id_off *)(ps + 1);
		for (ie = io + ps->nid; io < ie && ND_TTEST(*io); ++io) {
			ND_PRINT((ndo, "%c%s:%u", c, ipaddr_string(ndo, &io->id),
			    EXTRACT_32BITS(&io->off)));
			c = ',';
		}
		ND_PRINT((ndo, ">"));
		ps = (const struct pgstate *)io;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -263,9 +263,8 @@
 	const u_char *ep = ndo->ndo_snapend;
 
 	ND_PRINT((ndo, " wb-prep:"));
-	if (len < sizeof(*prep)) {
-		return (-1);
-	}
+	if (len < sizeof(*prep) || !ND_TTEST(*prep))
+		return (-1);
 	n = EXTRACT_32BITS(&prep->pp_n);
 	ps = (const struct pgstate *)(prep + 1);
 	while (--n >= 0 && ND_TTEST(*ps)) {
@@ -419,31 +418,37 @@
 	case PT_ID:
 		if (wb_id(ndo, (const struct pkt_id *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	case PT_RREQ:
 		if (wb_rreq(ndo, (const struct pkt_rreq *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	case PT_RREP:
 		if (wb_rrep(ndo, (const struct pkt_rrep *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	case PT_DRAWOP:
 		if (wb_drawop(ndo, (const struct pkt_dop *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	case PT_PREQ:
 		if (wb_preq(ndo, (const struct pkt_preq *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	case PT_PREP:
 		if (wb_prep(ndo, (const struct pkt_prep *)(ph + 1), len) >= 0)
 			return;
+		ND_PRINT((ndo, "%s", tstr));
 		break;
 
 	default:
```
