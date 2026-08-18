# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2712_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2712_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 718-758 of the vulnerable file.

trunc:
	return (1);
}

static int
ospf6_decode_v3(netdissect_options *ndo,
                register const struct ospf6hdr *op,
                register const u_char *dataend)
{
	register const rtrid_t *ap;
	register const struct lsr6 *lsrp;
	register const struct lsa6_hdr *lshp;
	register const struct lsa6 *lsap;
	register int i;

	switch (op->ospf6_type) {

	case OSPF_TYPE_HELLO: {
		register const struct hello6 *hellop = (const struct hello6 *)((const uint8_t *)op + OSPF6HDR_LEN);

		ND_PRINT((ndo, "\n\tOptions [%s]",
		          bittok2str(ospf6_option_values, "none",
		          EXTRACT_32BITS(&hellop->hello_options))));

		ND_TCHECK(hellop->hello_deadint);
		ND_PRINT((ndo, "\n\t  Hello Timer %us, Dead Timer %us, Interface-ID %s, Priority %u",
		          EXTRACT_16BITS(&hellop->hello_helloint),
		          EXTRACT_16BITS(&hellop->hello_deadint),
		          ipaddr_string(ndo, &hellop->hello_ifid),
		          hellop->hello_priority));

		ND_TCHECK(hellop->hello_dr);
		if (EXTRACT_32BITS(&hellop->hello_dr) != 0)
			ND_PRINT((ndo, "\n\t  Designated Router %s",
			    ipaddr_string(ndo, &hellop->hello_dr)));
		ND_TCHECK(hellop->hello_bdr);
		if (EXTRACT_32BITS(&hellop->hello_bdr) != 0)
			ND_PRINT((ndo, ", Backup Designated Router %s",
			    ipaddr_string(ndo, &hellop->hello_bdr)));
		if (ndo->ndo_vflag > 1) {
			ND_PRINT((ndo, "\n\t  Neighbor List:"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -735,6 +735,7 @@
 	case OSPF_TYPE_HELLO: {
 		register const struct hello6 *hellop = (const struct hello6 *)((const uint8_t *)op + OSPF6HDR_LEN);
 
+		ND_TCHECK_32BITS(&hellop->hello_options);
 		ND_PRINT((ndo, "\n\tOptions [%s]",
 		          bittok2str(ospf6_option_values, "none",
 		          EXTRACT_32BITS(&hellop->hello_options))));
```
