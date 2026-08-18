# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4849_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4849_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 131-171 of the vulnerable file.

  int width, int height, int stride, int numlvls)
{
	if (width > 0 && height > 0) {
		if ((*tsfb->qmfb->analyze)(a, xstart, ystart, width, height, stride))
			return -1;
		if (numlvls > 0) {
			if (jpc_tsfb_analyze2(tsfb, a, JPC_CEILDIVPOW2(xstart,
			  1), JPC_CEILDIVPOW2(ystart, 1), JPC_CEILDIVPOW2(
			  xstart + width, 1) - JPC_CEILDIVPOW2(xstart, 1),
			  JPC_CEILDIVPOW2(ystart + height, 1) -
			  JPC_CEILDIVPOW2(ystart, 1), stride, numlvls - 1)) {
				return -1;
			}
		}
	}
	return 0;
}

int jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)
{
	return (tsfb->numlvls > 0) ? jpc_tsfb_synthesize2(tsfb,
	  jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),
	  jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),
	  jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;
}

int jpc_tsfb_synthesize2(jpc_tsfb_t *tsfb, int *a, int xstart, int ystart,
  int width, int height, int stride, int numlvls)
{
	if (numlvls > 0) {
		if (jpc_tsfb_synthesize2(tsfb, a, JPC_CEILDIVPOW2(xstart, 1),
		  JPC_CEILDIVPOW2(ystart, 1), JPC_CEILDIVPOW2(xstart + width,
		  1) - JPC_CEILDIVPOW2(xstart, 1), JPC_CEILDIVPOW2(ystart +
		  height, 1) - JPC_CEILDIVPOW2(ystart, 1), stride, numlvls -
		  1)) {
			return -1;
		}
	}
	if (width > 0 && height > 0) {
		if ((*tsfb->qmfb->synthesize)(a, xstart, ystart, width, height, stride)) {
			return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,7 +148,8 @@
 
 int jpc_tsfb_synthesize(jpc_tsfb_t *tsfb, jas_seq2d_t *a)
 {
-	return (tsfb->numlvls > 0) ? jpc_tsfb_synthesize2(tsfb,
+	return (tsfb->numlvls > 0 && jas_seq2d_size(a)) ?
+	  jpc_tsfb_synthesize2(tsfb,
 	  jas_seq2d_getref(a, jas_seq2d_xstart(a), jas_seq2d_ystart(a)),
 	  jas_seq2d_xstart(a), jas_seq2d_ystart(a), jas_seq2d_width(a),
 	  jas_seq2d_height(a), jas_seq2d_rowstep(a), tsfb->numlvls - 1) : 0;
```
