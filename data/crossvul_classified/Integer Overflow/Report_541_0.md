# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 541_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `541_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 731-771 of the vulnerable file.

                                        OPJ_UINT32 p_tileno,
                                        OPJ_INT32 * p_tx0,
                                        OPJ_INT32  * p_tx1,
                                        OPJ_INT32  * p_ty0,
                                        OPJ_INT32  * p_ty1,
                                        OPJ_UINT32 * p_dx_min,
                                        OPJ_UINT32 * p_dy_min,
                                        OPJ_UINT32 * p_max_prec,
                                        OPJ_UINT32 * p_max_res)
{
    /* loop */
    OPJ_UINT32  compno, resno;
    /* pointers */
    const opj_tcp_t *l_tcp = 00;
    const opj_tccp_t * l_tccp = 00;
    const opj_image_comp_t * l_img_comp = 00;

    /* position in x and y of tile */
    OPJ_UINT32 p, q;

    /* preconditions */
    assert(p_cp != 00);
    assert(p_image != 00);
    assert(p_tileno < p_cp->tw * p_cp->th);

    /* initializations */
    l_tcp = &p_cp->tcps [p_tileno];
    l_img_comp = p_image->comps;
    l_tccp = l_tcp->tccps;

    /* here calculation of tx0, tx1, ty0, ty1, maxprec, dx and dy */
    p = p_tileno % p_cp->tw;
    q = p_tileno / p_cp->tw;

    /* find extent of tile */
    *p_tx0 = opj_int_max((OPJ_INT32)(p_cp->tx0 + p * p_cp->tdx),
                         (OPJ_INT32)p_image->x0);
    *p_tx1 = opj_int_min((OPJ_INT32)(p_cp->tx0 + (p + 1) * p_cp->tdx),
                         (OPJ_INT32)p_image->x1);
    *p_ty0 = opj_int_max((OPJ_INT32)(p_cp->ty0 + q * p_cp->tdy),
                         (OPJ_INT32)p_image->y0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -748,6 +748,9 @@
     /* position in x and y of tile */
     OPJ_UINT32 p, q;
 
+    /* non-corrected (in regard to image offset) tile offset */
+    OPJ_UINT32 l_tx0, l_ty0;
+
     /* preconditions */
     assert(p_cp != 00);
     assert(p_image != 00);
@@ -763,14 +766,14 @@
     q = p_tileno / p_cp->tw;
 
     /* find extent of tile */
-    *p_tx0 = opj_int_max((OPJ_INT32)(p_cp->tx0 + p * p_cp->tdx),
-                         (OPJ_INT32)p_image->x0);
-    *p_tx1 = opj_int_min((OPJ_INT32)(p_cp->tx0 + (p + 1) * p_cp->tdx),
-                         (OPJ_INT32)p_image->x1);
-    *p_ty0 = opj_int_max((OPJ_INT32)(p_cp->ty0 + q * p_cp->tdy),
-                         (OPJ_INT32)p_image->y0);
-    *p_ty1 = opj_int_min((OPJ_INT32)(p_cp->ty0 + (q + 1) * p_cp->tdy),
-                         (OPJ_INT32)p_image->y1);
+    l_tx0 = p_cp->tx0 + p *
+            p_cp->tdx; /* can't be greater than p_image->x1 so won't overflow */
+    *p_tx0 = (OPJ_INT32)opj_uint_max(l_tx0, p_image->x0);
+    *p_tx1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_tx0, p_cp->tdx), p_image->x1);
+    l_ty0 = p_cp->ty0 + q *
+            p_cp->tdy; /* can't be greater than p_image->y1 so won't overflow */
+    *p_ty0 = (OPJ_INT32)opj_uint_max(l_ty0, p_image->y0);
+    *p_ty1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_ty0, p_cp->tdy), p_image->y1);
 
     /* max precision is 0 (can only grow) */
     *p_max_prec = 0;
```
