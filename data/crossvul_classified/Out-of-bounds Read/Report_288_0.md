# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 288_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `288_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 372-413 of the vulnerable file.

};

static void
ospf6_print_ls_type(netdissect_options *ndo,
                    register u_int ls_type, register const rtrid_t *ls_stateid)
{
        ND_PRINT((ndo, "\n\t    %s LSA (%d), %s Scope%s, LSA-ID %s",
               tok2str(ospf6_lsa_values, "Unknown", ls_type & LS_TYPE_MASK),
               ls_type & LS_TYPE_MASK,
               tok2str(ospf6_ls_scope_values, "Unknown", ls_type & LS_SCOPE_MASK),
               ls_type &0x8000 ? ", transitive" : "", /* U-bit */
               ipaddr_string(ndo, ls_stateid)));
}

static int
ospf6_print_lshdr(netdissect_options *ndo,
                  register const struct lsa6_hdr *lshp, const u_char *dataend)
{
	if ((const u_char *)(lshp + 1) > dataend)
		goto trunc;
	ND_TCHECK(lshp->ls_type);
	ND_TCHECK(lshp->ls_seq);

	ND_PRINT((ndo, "\n\t  Advertising Router %s, seq 0x%08x, age %us, length %u",
               ipaddr_string(ndo, &lshp->ls_router),
               EXTRACT_32BITS(&lshp->ls_seq),
               EXTRACT_16BITS(&lshp->ls_age),
               EXTRACT_16BITS(&lshp->ls_length)-(u_int)sizeof(struct lsa6_hdr)));

	ospf6_print_ls_type(ndo, EXTRACT_16BITS(&lshp->ls_type), &lshp->ls_stateid);

	return (0);
trunc:
	return (1);
}

static int
ospf6_print_lsaprefix(netdissect_options *ndo,
                      const uint8_t *tptr, u_int lsa_length)
{
	const struct lsa6_prefix *lsapp = (const struct lsa6_prefix *)tptr;
	u_int wordlen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,8 +389,7 @@
 {
 	if ((const u_char *)(lshp + 1) > dataend)
 		goto trunc;
-	ND_TCHECK(lshp->ls_type);
-	ND_TCHECK(lshp->ls_seq);
+	ND_TCHECK(lshp->ls_length);	/* last field of struct lsa6_hdr */
 
 	ND_PRINT((ndo, "\n\t  Advertising Router %s, seq 0x%08x, age %us, length %u",
                ipaddr_string(ndo, &lshp->ls_router),
```
