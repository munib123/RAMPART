# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 4866_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4866_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 352-392 of the vulnerable file.

            for (pi->x = pi->poc.tx0; pi->x < pi->poc.tx1;
                    pi->x += (OPJ_INT32)(pi->dx - (OPJ_UINT32)(pi->x % (OPJ_INT32)pi->dx))) {
                for (pi->compno = pi->poc.compno0; pi->compno < pi->poc.compno1; pi->compno++) {
                    OPJ_UINT32 levelno;
                    OPJ_INT32 trx0, try0;
                    OPJ_INT32  trx1, try1;
                    OPJ_UINT32  rpx, rpy;
                    OPJ_INT32  prci, prcj;
                    comp = &pi->comps[pi->compno];
                    if (pi->resno >= comp->numresolutions) {
                        continue;
                    }
                    res = &comp->resolutions[pi->resno];
                    levelno = comp->numresolutions - 1 - pi->resno;
                    trx0 = opj_int_ceildiv(pi->tx0, (OPJ_INT32)(comp->dx << levelno));
                    try0 = opj_int_ceildiv(pi->ty0, (OPJ_INT32)(comp->dy << levelno));
                    trx1 = opj_int_ceildiv(pi->tx1, (OPJ_INT32)(comp->dx << levelno));
                    try1 = opj_int_ceildiv(pi->ty1, (OPJ_INT32)(comp->dy << levelno));
                    rpx = res->pdx + levelno;
                    rpy = res->pdy + levelno;
                    if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                            ((try0 << levelno) % (1 << rpy))))) {
                        continue;
                    }
                    if (!((pi->x % (OPJ_INT32)(comp->dx << rpx) == 0) || ((pi->x == pi->tx0) &&
                            ((trx0 << levelno) % (1 << rpx))))) {
                        continue;
                    }

                    if ((res->pw == 0) || (res->ph == 0)) {
                        continue;
                    }

                    if ((trx0 == trx1) || (try0 == try1)) {
                        continue;
                    }

                    prci = opj_int_floordivpow2(opj_int_ceildiv(pi->x,
                                                (OPJ_INT32)(comp->dx << levelno)), (OPJ_INT32)res->pdx)
                           - opj_int_floordivpow2(trx0, (OPJ_INT32)res->pdx);
                    prcj = opj_int_floordivpow2(opj_int_ceildiv(pi->y,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -369,6 +369,17 @@
                     try1 = opj_int_ceildiv(pi->ty1, (OPJ_INT32)(comp->dy << levelno));
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    /* in below tests */
+                    /* Fixes reading id:000026,sig:08,src:002419,op:int32,pos:60,val:+32 */
+                    /* of https://github.com/uclouvain/openjpeg/issues/938 */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
+                    /* See ISO-15441. B.12.1.3 Resolution level-position-component-layer progression */
                     if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
@@ -464,6 +475,17 @@
                     try1 = opj_int_ceildiv(pi->ty1, (OPJ_INT32)(comp->dy << levelno));
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    /* in below tests */
+                    /* Relates to id:000019,sig:08,src:001098,op:flip1,pos:49 */
+                    /* of https://github.com/uclouvain/openjpeg/issues/938 */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
+                    /* See ISO-15441. B.12.1.4 Position-component-resolution level-layer progression */
                     if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
@@ -557,6 +579,17 @@
                     try1 = opj_int_ceildiv(pi->ty1, (OPJ_INT32)(comp->dy << levelno));
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    /* in below tests */
+                    /* Fixes reading id:000019,sig:08,src:001098,op:flip1,pos:49 */
+                    /* of https://github.com/uclouvain/openjpeg/issues/938 */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
+                    /* See ISO-15441. B.12.1.5 Component-position-resolution level-layer progression */
                     if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
```
