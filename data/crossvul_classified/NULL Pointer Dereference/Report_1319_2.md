# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1319_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1319_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 878-918 of the vulnerable file.

  (void)sqlite3WalkExprList(&sWalker, pEList);

  *ppSub = sRewrite.pSub;
}

/*
** Append a copy of each expression in expression-list pAppend to
** expression list pList. Return a pointer to the result list.
*/
static ExprList *exprListAppendList(
  Parse *pParse,          /* Parsing context */
  ExprList *pList,        /* List to which to append. Might be NULL */
  ExprList *pAppend,      /* List of values to append. Might be NULL */
  int bIntToNull
){
  if( pAppend ){
    int i;
    int nInit = pList ? pList->nExpr : 0;
    for(i=0; i<pAppend->nExpr; i++){
      Expr *pDup = sqlite3ExprDup(pParse->db, pAppend->a[i].pExpr, 0);
      if( bIntToNull && pDup && pDup->op==TK_INTEGER ){
        pDup->op = TK_NULL;
        pDup->flags &= ~(EP_IntValue|EP_IsTrue|EP_IsFalse);
      }
      pList = sqlite3ExprListAppend(pParse, pList, pDup);
      if( pList ) pList->a[nInit+i].sortFlags = pAppend->a[i].sortFlags;
    }
  }
  return pList;
}

/*
** If the SELECT statement passed as the second argument does not invoke
** any SQL window functions, this function is a no-op. Otherwise, it 
** rewrites the SELECT statement so that window function xStep functions
** are invoked in the correct order as described under "SELECT REWRITING"
** at the top of this file.
*/
int sqlite3WindowRewrite(Parse *pParse, Select *p){
  int rc = SQLITE_OK;
  if( p->pWin && p->pPrior==0 && (p->selFlags & SF_WinRewrite)==0 ){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -895,9 +895,11 @@
     int nInit = pList ? pList->nExpr : 0;
     for(i=0; i<pAppend->nExpr; i++){
       Expr *pDup = sqlite3ExprDup(pParse->db, pAppend->a[i].pExpr, 0);
+      assert( pDup==0 || !ExprHasProperty(pDup, EP_MemToken) );
       if( bIntToNull && pDup && pDup->op==TK_INTEGER ){
         pDup->op = TK_NULL;
         pDup->flags &= ~(EP_IntValue|EP_IsTrue|EP_IsFalse);
+        pDup->u.zToken = 0;
       }
       pList = sqlite3ExprListAppend(pParse, pList, pDup);
       if( pList ) pList->a[nInit+i].sortFlags = pAppend->a[i].sortFlags;
```
