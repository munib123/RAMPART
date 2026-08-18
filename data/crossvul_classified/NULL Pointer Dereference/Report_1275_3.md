# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1275_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1275_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1124-1164 of the vulnerable file.

  if( sqlite3ExprCompare(0, pExpr, pX->pIdxExpr, pX->iTabCur)==0 ){
    pExpr->affExpr = sqlite3ExprAffinity(pExpr);
    pExpr->op = TK_COLUMN;
    pExpr->iTable = pX->iIdxCur;
    pExpr->iColumn = pX->iIdxCol;
    pExpr->y.pTab = 0;
    return WRC_Prune;
  }else{
    return WRC_Continue;
  }
}

#ifndef SQLITE_OMIT_GENERATED_COLUMNS
/* A walker node callback that translates a column reference to a table
** into a corresponding column reference of an index.
*/
static int whereIndexExprTransColumn(Walker *p, Expr *pExpr){
  if( pExpr->op==TK_COLUMN ){
    IdxExprTrans *pX = p->u.pIdxTrans;
    if( pExpr->iTable==pX->iTabCur && pExpr->iColumn==pX->iTabCol ){
      pExpr->iTable = pX->iIdxCur;
      pExpr->iColumn = pX->iIdxCol;
      pExpr->y.pTab = 0;
    }
  }
  return WRC_Continue;
}
#endif /* SQLITE_OMIT_GENERATED_COLUMNS */

/*
** For an indexes on expression X, locate every instance of expression X
** in pExpr and change that subexpression into a reference to the appropriate
** column of the index.
**
** 2019-10-24: Updated to also translate references to a VIRTUAL column in
** the table into references to the corresponding (stored) column of the
** index.
*/
static void whereIndexExprTrans(
  Index *pIdx,      /* The Index */
  int iTabCur,      /* Cursor of the table that is being indexed */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1141,6 +1141,8 @@
   if( pExpr->op==TK_COLUMN ){
     IdxExprTrans *pX = p->u.pIdxTrans;
     if( pExpr->iTable==pX->iTabCur && pExpr->iColumn==pX->iTabCol ){
+      assert( pExpr->y.pTab!=0 );
+      pExpr->affExpr = sqlite3TableColumnAffinity(pExpr->y.pTab,pExpr->iColumn);
       pExpr->iTable = pX->iIdxCur;
       pExpr->iColumn = pX->iIdxCol;
       pExpr->y.pTab = 0;
```
