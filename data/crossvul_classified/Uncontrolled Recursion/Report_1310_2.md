# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 1310_2
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1310_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 743-783 of the vulnerable file.

  if( pSelect->pWith ){
    int i;
    for(i=0; i<pSelect->pWith->nCte; i++){
      Select *p = pSelect->pWith->a[i].pSelect;
      NameContext sNC;
      memset(&sNC, 0, sizeof(sNC));
      sNC.pParse = pWalker->pParse;
      sqlite3SelectPrep(sNC.pParse, p, &sNC);
      sqlite3WalkSelect(pWalker, p);
    }
  }
}

/*
** Walker callback used by sqlite3RenameExprUnmap().
*/
static int renameUnmapSelectCb(Walker *pWalker, Select *p){
  Parse *pParse = pWalker->pParse;
  int i;
  if( pParse->nErr ) return WRC_Abort;
  if( ALWAYS(p->pEList) ){
    ExprList *pList = p->pEList;
    for(i=0; i<pList->nExpr; i++){
      if( pList->a[i].zName ){
        sqlite3RenameTokenRemap(pParse, 0, (void*)pList->a[i].zName);
      }
    }
  }
  if( ALWAYS(p->pSrc) ){  /* Every Select as a SrcList, even if it is empty */
    SrcList *pSrc = p->pSrc;
    for(i=0; i<pSrc->nSrc; i++){
      sqlite3RenameTokenRemap(pParse, 0, (void*)pSrc->a[i].zName);
    }
  }

  renameWalkWith(pWalker, p);
  return WRC_Continue;
}

/*
** Remove all nodes that are part of expression pExpr from the rename list.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -760,6 +760,7 @@
   Parse *pParse = pWalker->pParse;
   int i;
   if( pParse->nErr ) return WRC_Abort;
+  if( p->selFlags & SF_View ) return WRC_Prune;
   if( ALWAYS(p->pEList) ){
     ExprList *pList = p->pEList;
     for(i=0; i<pList->nExpr; i++){
@@ -851,6 +852,7 @@
 ** descend into sub-select statements.
 */
 static int renameColumnSelectCb(Walker *pWalker, Select *p){
+  if( p->selFlags & SF_View ) return WRC_Prune;
   renameWalkWith(pWalker, p);
   return WRC_Continue;
 }
@@ -1316,8 +1318,9 @@
   if( sParse.pNewTable ){
     Select *pSelect = sParse.pNewTable->pSelect;
     if( pSelect ){
+      pSelect->selFlags &= ~SF_View;
       sParse.rc = SQLITE_OK;
-      sqlite3SelectPrep(&sParse, sParse.pNewTable->pSelect, 0);
+      sqlite3SelectPrep(&sParse, pSelect, 0);
       rc = (db->mallocFailed ? SQLITE_NOMEM : sParse.rc);
       if( rc==SQLITE_OK ){
         sqlite3WalkSelect(&sWalker, pSelect);
@@ -1434,6 +1437,7 @@
   int i;
   RenameCtx *p = pWalker->u.pRename;
   SrcList *pSrc = pSelect->pSrc;
+  if( pSelect->selFlags & SF_View ) return WRC_Prune;
   if( pSrc==0 ){
     assert( pWalker->pParse->db->mallocFailed );
     return WRC_Abort;
@@ -1513,10 +1517,13 @@
 
         if( pTab->pSelect ){
           if( isLegacy==0 ){
+            Select *pSelect = pTab->pSelect;
             NameContext sNC;
             memset(&sNC, 0, sizeof(sNC));
             sNC.pParse = &sParse;
 
+            assert( pSelect->selFlags & SF_View );
+            pSelect->selFlags &= ~SF_View;
             sqlite3SelectPrep(&sParse, pTab->pSelect, &sNC);
             if( sParse.nErr ) rc = sParse.rc;
             sqlite3WalkSelect(&sWalker, pTab->pSelect);
```
