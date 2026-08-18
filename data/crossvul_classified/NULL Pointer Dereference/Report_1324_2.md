# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1324_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1324_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3583-3623 of the vulnerable file.

** avoided.
**
** Flattening is subject to the following constraints:
**
**  (**)  We no longer attempt to flatten aggregate subqueries. Was:
**        The subquery and the outer query cannot both be aggregates.
**
**  (**)  We no longer attempt to flatten aggregate subqueries. Was:
**        (2) If the subquery is an aggregate then
**        (2a) the outer query must not be a join and
**        (2b) the outer query must not use subqueries
**             other than the one FROM-clause subquery that is a candidate
**             for flattening.  (This is due to ticket [2f7170d73bf9abf80]
**             from 2015-02-09.)
**
**   (3)  If the subquery is the right operand of a LEFT JOIN then
**        (3a) the subquery may not be a join and
**        (3b) the FROM clause of the subquery may not contain a virtual
**             table and
**        (3c) the outer query may not be an aggregate.
**
**   (4)  The subquery can not be DISTINCT.
**
**  (**)  At one point restrictions (4) and (5) defined a subset of DISTINCT
**        sub-queries that were excluded from this optimization. Restriction 
**        (4) has since been expanded to exclude all DISTINCT subqueries.
**
**  (**)  We no longer attempt to flatten aggregate subqueries.  Was:
**        If the subquery is aggregate, the outer query may not be DISTINCT.
**
**   (7)  The subquery must have a FROM clause.  TODO:  For subqueries without
**        A FROM clause, consider adding a FROM clause with the special
**        table sqlite_once that consists of a single row containing a
**        single NULL.
**
**   (8)  If the subquery uses LIMIT then the outer query may not be a join.
**
**   (9)  If the subquery uses LIMIT then the outer query may not be aggregate.
**
**  (**)  Restriction (10) was removed from the code on 2005-02-05 but we
**        accidently carried the comment forward until 2014-09-15.  Original
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3600,6 +3600,7 @@
 **        (3b) the FROM clause of the subquery may not contain a virtual
 **             table and
 **        (3c) the outer query may not be an aggregate.
+**        (3d) the outer query may not be DISTINCT.
 **
 **   (4)  The subquery can not be DISTINCT.
 **
@@ -3796,8 +3797,11 @@
   */
   if( (pSubitem->fg.jointype & JT_OUTER)!=0 ){
     isLeftJoin = 1;
-    if( pSubSrc->nSrc>1 || isAgg || IsVirtual(pSubSrc->a[0].pTab) ){
-      /*  (3a)             (3c)     (3b) */
+    if( pSubSrc->nSrc>1                   /* (3a) */
+     || isAgg                             /* (3b) */
+     || IsVirtual(pSubSrc->a[0].pTab)     /* (3c) */
+     || (p->selFlags & SF_Distinct)!=0    /* (3d) */
+    ){
       return 0;
     }
   }
```
