# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 538_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `538_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 207-247 of the vulnerable file.

            for (pi->x = pi->poc.tx0; pi->x < pi->poc.tx1;
                    pi->x += pi->dx - (pi->x % pi->dx)) {
                for (pi->compno = pi->poc.compno0; pi->compno < pi->poc.compno1; pi->compno++) {
                    int levelno;
                    int trx0, try0;
                    int trx1, try1;
                    int rpx, rpy;
                    int prci, prcj;
                    comp = &pi->comps[pi->compno];
                    if (pi->resno >= comp->numresolutions) {
                        continue;
                    }
                    res = &comp->resolutions[pi->resno];
                    levelno = comp->numresolutions - 1 - pi->resno;
                    trx0 = int_ceildiv(pi->tx0, comp->dx << levelno);
                    try0 = int_ceildiv(pi->ty0, comp->dy << levelno);
                    trx1 = int_ceildiv(pi->tx1, comp->dx << levelno);
                    try1 = int_ceildiv(pi->ty1, comp->dy << levelno);
                    rpx = res->pdx + levelno;
                    rpy = res->pdy + levelno;
                    if (!((pi->y % (comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                            ((try0 << levelno) % (1 << rpy))))) {
                        continue;
                    }
                    if (!((pi->x % (comp->dx << rpx) == 0) || ((pi->x == pi->tx0) &&
                            ((trx0 << levelno) % (1 << rpx))))) {
                        continue;
                    }

                    if ((res->pw == 0) || (res->ph == 0)) {
                        continue;
                    }

                    if ((trx0 == trx1) || (try0 == try1)) {
                        continue;
                    }

                    prci = int_floordivpow2(int_ceildiv(pi->x, comp->dx << levelno), res->pdx)
                           - int_floordivpow2(trx0, res->pdx);
                    prcj = int_floordivpow2(int_ceildiv(pi->y, comp->dy << levelno), res->pdy)
                           - int_floordivpow2(try0, res->pdy);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,6 +224,13 @@
                     try1 = int_ceildiv(pi->ty1, comp->dy << levelno);
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
                     if (!((pi->y % (comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
@@ -317,6 +324,13 @@
                     try1 = int_ceildiv(pi->ty1, comp->dy << levelno);
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
                     if (!((pi->y % (comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
@@ -408,6 +422,13 @@
                     try1 = int_ceildiv(pi->ty1, comp->dy << levelno);
                     rpx = res->pdx + levelno;
                     rpy = res->pdy + levelno;
+
+                    /* To avoid divisions by zero / undefined behaviour on shift */
+                    if (rpx >= 31 || ((comp->dx << rpx) >> rpx) != comp->dx ||
+                            rpy >= 31 || ((comp->dy << rpy) >> rpy) != comp->dy) {
+                        continue;
+                    }
+
                     if (!((pi->y % (comp->dy << rpy) == 0) || ((pi->y == pi->ty0) &&
                             ((try0 << levelno) % (1 << rpy))))) {
                         continue;
```
