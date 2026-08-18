# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 1310_3
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1310_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 2468-2508 of the vulnerable file.

  int iDb;
  sqlite3 *db = pParse->db;

  if( pParse->nVar>0 ){
    sqlite3ErrorMsg(pParse, "parameters are not allowed in views");
    goto create_view_fail;
  }
  sqlite3StartTable(pParse, pName1, pName2, isTemp, 1, 0, noErr);
  p = pParse->pNewTable;
  if( p==0 || pParse->nErr ) goto create_view_fail;
  sqlite3TwoPartName(pParse, pName1, pName2, &pName);
  iDb = sqlite3SchemaToIndex(db, p->pSchema);
  sqlite3FixInit(&sFix, pParse, iDb, "view", pName);
  if( sqlite3FixSelect(&sFix, pSelect) ) goto create_view_fail;

  /* Make a copy of the entire SELECT statement that defines the view.
  ** This will force all the Expr.token.z values to be dynamically
  ** allocated rather than point to the input string - which means that
  ** they will persist after the current sqlite3_exec() call returns.
  */
  if( IN_RENAME_OBJECT ){
    p->pSelect = pSelect;
    pSelect = 0;
  }else{
    p->pSelect = sqlite3SelectDup(db, pSelect, EXPRDUP_REDUCE);
  }
  p->pCheck = sqlite3ExprListDup(db, pCNames, EXPRDUP_REDUCE);
  if( db->mallocFailed ) goto create_view_fail;

  /* Locate the end of the CREATE VIEW statement.  Make sEnd point to
  ** the end.
  */
  sEnd = pParse->sLastToken;
  assert( sEnd.z[0]!=0 || sEnd.n==0 );
  if( sEnd.z[0]!=';' ){
    sEnd.z += sEnd.n;
  }
  sEnd.n = 0;
  n = (int)(sEnd.z - pBegin->z);
  assert( n>0 );
  z = pBegin->z;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2485,6 +2485,7 @@
   ** allocated rather than point to the input string - which means that
   ** they will persist after the current sqlite3_exec() call returns.
   */
+  pSelect->selFlags |= SF_View;
   if( IN_RENAME_OBJECT ){
     p->pSelect = pSelect;
     pSelect = 0;
```
