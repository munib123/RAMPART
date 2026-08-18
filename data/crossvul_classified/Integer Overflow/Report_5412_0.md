# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5412_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5412_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1178-1218 of the vulnerable file.

			jpc_dec_tilefini(dec, tile);
		}
	}

	/* We are done processing the code stream. */
	dec->state = JPC_MT;

	return 1;
}

static int jpc_dec_process_siz(jpc_dec_t *dec, jpc_ms_t *ms)
{
	jpc_siz_t *siz = &ms->parms.siz;
	int compno;
	int tileno;
	jpc_dec_tile_t *tile;
	jpc_dec_tcomp_t *tcomp;
	int htileno;
	int vtileno;
	jpc_dec_cmpt_t *cmpt;

	dec->xstart = siz->xoff;
	dec->ystart = siz->yoff;
	dec->xend = siz->width;
	dec->yend = siz->height;
	dec->tilewidth = siz->tilewidth;
	dec->tileheight = siz->tileheight;
	dec->tilexoff = siz->tilexoff;
	dec->tileyoff = siz->tileyoff;
	dec->numcomps = siz->numcomps;
	if (!(dec->cp = jpc_dec_cp_create(dec->numcomps))) {
		return -1;
	}

	if (!(dec->cmpts = jas_alloc2(dec->numcomps, sizeof(jpc_dec_cmpt_t)))) {
		return -1;
	}

	for (compno = 0, cmpt = dec->cmpts; compno < dec->numcomps; ++compno,
	  ++cmpt) {
		cmpt->prec = siz->comps[compno].prec;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1195,6 +1195,7 @@
 	int htileno;
 	int vtileno;
 	jpc_dec_cmpt_t *cmpt;
+	size_t size;
 
 	dec->xstart = siz->xoff;
 	dec->ystart = siz->yoff;
@@ -1231,7 +1232,10 @@
 
 	dec->numhtiles = JPC_CEILDIV(dec->xend - dec->tilexoff, dec->tilewidth);
 	dec->numvtiles = JPC_CEILDIV(dec->yend - dec->tileyoff, dec->tileheight);
-	dec->numtiles = dec->numhtiles * dec->numvtiles;
+	if (!jas_safe_size_mul(dec->numhtiles, dec->numvtiles, &size)) {
+		return -1;
+	}
+	dec->numtiles = size;
 	JAS_DBGLOG(10, ("numtiles = %d; numhtiles = %d; numvtiles = %d;\n",
 	  dec->numtiles, dec->numhtiles, dec->numvtiles));
 	if (!(dec->tiles = jas_alloc2(dec->numtiles, sizeof(jpc_dec_tile_t)))) {
```
