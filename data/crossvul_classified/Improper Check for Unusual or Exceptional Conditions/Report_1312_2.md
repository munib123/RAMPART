# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 1312_2
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1312_2`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 1579-1619 of the vulnerable file.

        sqlite3VdbeAddOp2(v, OP_Integer, 0, 7);
        for(j=0, pIdx=pTab->pIndex; pIdx; pIdx=pIdx->pNext, j++){
          sqlite3VdbeAddOp2(v, OP_Integer, 0, 8+j); /* index entries counter */
        }
        assert( pParse->nMem>=8+j );
        assert( sqlite3NoTempsInRange(pParse,1,7+j) );
        sqlite3VdbeAddOp2(v, OP_Rewind, iDataCur, 0); VdbeCoverage(v);
        loopTop = sqlite3VdbeAddOp2(v, OP_AddImm, 7, 1);
        if( !isQuick ){
          /* Sanity check on record header decoding */
          sqlite3VdbeAddOp3(v, OP_Column, iDataCur, pTab->nNVCol-1,3);
          sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
        }
        /* Verify that all NOT NULL columns really are NOT NULL */
        for(j=0; j<pTab->nCol; j++){
          char *zErr;
          int jmp2;
          if( j==pTab->iPKey ) continue;
          if( pTab->aCol[j].notNull==0 ) continue;
          sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, j, 3);
          sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
          jmp2 = sqlite3VdbeAddOp1(v, OP_NotNull, 3); VdbeCoverage(v);
          zErr = sqlite3MPrintf(db, "NULL value in %s.%s", pTab->zName,
                              pTab->aCol[j].zName);
          sqlite3VdbeAddOp4(v, OP_String8, 0, 3, 0, zErr, P4_DYNAMIC);
          integrityCheckResultRow(v);
          sqlite3VdbeJumpHere(v, jmp2);
        }
        /* Verify CHECK constraints */
        if( pTab->pCheck && (db->flags & SQLITE_IgnoreChecks)==0 ){
          ExprList *pCheck = sqlite3ExprListDup(db, pTab->pCheck, 0);
          if( db->mallocFailed==0 ){
            int addrCkFault = sqlite3VdbeMakeLabel(pParse);
            int addrCkOk = sqlite3VdbeMakeLabel(pParse);
            char *zErr;
            int k;
            pParse->iSelfTab = iDataCur + 1;
            for(k=pCheck->nExpr-1; k>0; k--){
              sqlite3ExprIfFalse(pParse, pCheck->a[k].pExpr, addrCkFault, 0);
            }
            sqlite3ExprIfTrue(pParse, pCheck->a[0].pExpr, addrCkOk, 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1596,7 +1596,9 @@
           if( j==pTab->iPKey ) continue;
           if( pTab->aCol[j].notNull==0 ) continue;
           sqlite3ExprCodeGetColumnOfTable(v, pTab, iDataCur, j, 3);
-          sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
+          if( sqlite3VdbeGetOp(v,-1)->opcode==OP_Column ){
+            sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
+          }
           jmp2 = sqlite3VdbeAddOp1(v, OP_NotNull, 3); VdbeCoverage(v);
           zErr = sqlite3MPrintf(db, "NULL value in %s.%s", pTab->zName,
                               pTab->aCol[j].zName);
```
