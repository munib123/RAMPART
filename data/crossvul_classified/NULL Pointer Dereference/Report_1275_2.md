# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1275_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1275_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3588-3628 of the vulnerable file.

      if( !pAggInfo->directMode ){
        assert( pCol->iMem>0 );
        return pCol->iMem;
      }else if( pAggInfo->useSortingIdx ){
        sqlite3VdbeAddOp3(v, OP_Column, pAggInfo->sortingIdxPTab,
                              pCol->iSorterColumn, target);
        return target;
      }
      /* Otherwise, fall thru into the TK_COLUMN case */
    }
    case TK_COLUMN: {
      int iTab = pExpr->iTable;
      if( ExprHasProperty(pExpr, EP_FixedCol) ){
        /* This COLUMN expression is really a constant due to WHERE clause
        ** constraints, and that constant is coded by the pExpr->pLeft
        ** expresssion.  However, make sure the constant has the correct
        ** datatype by applying the Affinity of the table column to the
        ** constant.
        */
        int iReg = sqlite3ExprCodeTarget(pParse, pExpr->pLeft,target);
        int aff = sqlite3TableColumnAffinity(pExpr->y.pTab, pExpr->iColumn);
        if( aff>SQLITE_AFF_BLOB ){
          static const char zAff[] = "B\000C\000D\000E";
          assert( SQLITE_AFF_BLOB=='A' );
          assert( SQLITE_AFF_TEXT=='B' );
          if( iReg!=target ){
            sqlite3VdbeAddOp2(v, OP_SCopy, iReg, target);
            iReg = target;
          }
          sqlite3VdbeAddOp4(v, OP_Affinity, iReg, 1, 0,
                            &zAff[(aff-'B')*2], P4_STATIC);
        }
        return iReg;
      }
      if( iTab<0 ){
        if( pParse->iSelfTab<0 ){
          /* Other columns in the same row for CHECK constraints or
          ** generated columns or for inserting into partial index.
          ** The row is unpacked into registers beginning at
          ** 0-(pParse->iSelfTab).  The rowid (if any) is in a register
          ** immediately prior to the first column.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3605,7 +3605,12 @@
         ** constant.
         */
         int iReg = sqlite3ExprCodeTarget(pParse, pExpr->pLeft,target);
-        int aff = sqlite3TableColumnAffinity(pExpr->y.pTab, pExpr->iColumn);
+        int aff;
+        if( pExpr->y.pTab ){
+          aff = sqlite3TableColumnAffinity(pExpr->y.pTab, pExpr->iColumn);
+        }else{
+          aff = pExpr->affExpr;
+        }
         if( aff>SQLITE_AFF_BLOB ){
           static const char zAff[] = "B\000C\000D\000E";
           assert( SQLITE_AFF_BLOB=='A' );
```
