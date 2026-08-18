# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5486_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5486_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 695-735 of the vulnerable file.

	uint_fast32_t tlcbgystart;
	uint_fast32_t brcbgxend;
	uint_fast32_t brcbgyend;
	uint_fast32_t cbgxstart;
	uint_fast32_t cbgystart;
	uint_fast32_t cbgxend;
	uint_fast32_t cbgyend;
	uint_fast32_t tlcblkxstart;
	uint_fast32_t tlcblkystart;
	uint_fast32_t brcblkxend;
	uint_fast32_t brcblkyend;
	uint_fast32_t cblkxstart;
	uint_fast32_t cblkystart;
	uint_fast32_t cblkxend;
	uint_fast32_t cblkyend;
	uint_fast32_t tmpxstart;
	uint_fast32_t tmpystart;
	uint_fast32_t tmpxend;
	uint_fast32_t tmpyend;
	jpc_dec_cp_t *cp;
	jpc_tsfb_band_t bnds[64];
	jpc_pchg_t *pchg;
	int pchgno;
	jpc_dec_cmpt_t *cmpt;

	cp = tile->cp;
	tile->realmode = 0;
	if (cp->mctid == JPC_MCT_ICT) {
		tile->realmode = 1;
	}

	for (compno = 0, tcomp = tile->tcomps, cmpt = dec->cmpts; compno <
	  dec->numcomps; ++compno, ++tcomp, ++cmpt) {
		ccp = &tile->cp->ccps[compno];
		if (ccp->qmfbid == JPC_COX_INS) {
			tile->realmode = 1;
		}
		tcomp->numrlvls = ccp->numrlvls;
		if (!(tcomp->rlvls = jas_alloc2(tcomp->numrlvls,
		  sizeof(jpc_dec_rlvl_t)))) {
			return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -712,7 +712,7 @@
 	uint_fast32_t tmpxend;
 	uint_fast32_t tmpyend;
 	jpc_dec_cp_t *cp;
-	jpc_tsfb_band_t bnds[64];
+	jpc_tsfb_band_t bnds[JPC_MAXBANDS];
 	jpc_pchg_t *pchg;
 	int pchgno;
 	jpc_dec_cmpt_t *cmpt;
```
