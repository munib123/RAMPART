# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in c
**Pair ID:** 1325_4
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1325_4`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```c
Lines 917-957 of the vulnerable file.

*/
int sqlite3WindowRewrite(Parse *pParse, Select *p){
  int rc = SQLITE_OK;
  if( p->pWin && p->pPrior==0 && (p->selFlags & SF_WinRewrite)==0 ){
    Vdbe *v = sqlite3GetVdbe(pParse);
    sqlite3 *db = pParse->db;
    Select *pSub = 0;             /* The subquery */
    SrcList *pSrc = p->pSrc;
    Expr *pWhere = p->pWhere;
    ExprList *pGroupBy = p->pGroupBy;
    Expr *pHaving = p->pHaving;
    ExprList *pSort = 0;

    ExprList *pSublist = 0;       /* Expression list for sub-query */
    Window *pMWin = p->pWin;      /* Master window object */
    Window *pWin;                 /* Window object iterator */
    Table *pTab;

    pTab = sqlite3DbMallocZero(db, sizeof(Table));
    if( pTab==0 ){
      return SQLITE_NOMEM;
    }

    p->pSrc = 0;
    p->pWhere = 0;
    p->pGroupBy = 0;
    p->pHaving = 0;
    p->selFlags &= ~SF_Aggregate;
    p->selFlags |= SF_WinRewrite;

    /* Create the ORDER BY clause for the sub-select. This is the concatenation
    ** of the window PARTITION and ORDER BY clauses. Then, if this makes it
    ** redundant, remove the ORDER BY from the parent SELECT.  */
    pSort = sqlite3ExprListDup(db, pMWin->pPartition, 0);
    pSort = exprListAppendList(pParse, pSort, pMWin->pOrderBy, 1);
    if( pSort && p->pOrderBy && p->pOrderBy->nExpr<=pSort->nExpr ){
      int nSave = pSort->nExpr;
      pSort->nExpr = p->pOrderBy->nExpr;
      if( sqlite3ExprListCompare(pSort, p->pOrderBy, -1)==0 ){
        sqlite3ExprListDelete(db, p->pOrderBy);
        p->pOrderBy = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -934,7 +934,7 @@
 
     pTab = sqlite3DbMallocZero(db, sizeof(Table));
     if( pTab==0 ){
-      return SQLITE_NOMEM;
+      return sqlite3ErrorToParser(db, SQLITE_NOMEM);
     }
 
     p->pSrc = 0;
@@ -1039,6 +1039,10 @@
     sqlite3DbFree(db, pTab);
   }
 
+  if( rc && pParse->nErr==0 ){
+    assert( pParse->db->mallocFailed );
+    return sqlite3ErrorToParser(pParse->db, SQLITE_NOMEM);
+  }
   return rc;
 }
 
```
