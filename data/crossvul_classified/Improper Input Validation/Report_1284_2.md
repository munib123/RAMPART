# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1284_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1284_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 534-576 of the vulnerable file.

  /*
  ** cnt==0 means there was not match.  cnt>1 means there were two or
  ** more matches.  Either way, we have an error.
  */
  if( cnt!=1 ){
    const char *zErr;
    zErr = cnt==0 ? "no such column" : "ambiguous column name";
    if( zDb ){
      sqlite3ErrorMsg(pParse, "%s: %s.%s.%s", zErr, zDb, zTab, zCol);
    }else if( zTab ){
      sqlite3ErrorMsg(pParse, "%s: %s.%s", zErr, zTab, zCol);
    }else{
      sqlite3ErrorMsg(pParse, "%s: %s", zErr, zCol);
    }
    pParse->checkSchema = 1;
    pTopNC->nErr++;
  }

  /* If a column from a table in pSrcList is referenced, then record
  ** this fact in the pSrcList.a[].colUsed bitmask.  Column 0 causes
  ** bit 0 to be set.  Column 1 sets bit 1.  And so forth.  If the
  ** column number is greater than the number of bits in the bitmask
  ** then set the high-order bit of the bitmask.
  */
  if( pExpr->iColumn>=0 && pMatch!=0 ){
    int n = pExpr->iColumn;
    testcase( n==BMS-1 );
    if( n>=BMS ){
      n = BMS-1;
    }
    assert( pMatch->iCursor==pExpr->iTable );
    pMatch->colUsed |= ((Bitmask)1)<<n;
  }

  /* Clean up and return
  */
  sqlite3ExprDelete(db, pExpr->pLeft);
  pExpr->pLeft = 0;
  sqlite3ExprDelete(db, pExpr->pRight);
  pExpr->pRight = 0;
  pExpr->op = eNewExprOp;
  ExprSetProperty(pExpr, EP_Leaf);
lookupname_end:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -551,9 +551,18 @@
 
   /* If a column from a table in pSrcList is referenced, then record
   ** this fact in the pSrcList.a[].colUsed bitmask.  Column 0 causes
-  ** bit 0 to be set.  Column 1 sets bit 1.  And so forth.  If the
-  ** column number is greater than the number of bits in the bitmask
-  ** then set the high-order bit of the bitmask.
+  ** bit 0 to be set.  Column 1 sets bit 1.  And so forth.
+  **
+  ** The colUsed mask is an optimization used to help determine if an
+  ** index is a covering index.  The correct answer is still obtained
+  ** if the mask contains extra bits.  But omitting bits from the mask
+  ** might result in an incorrect answer.
+  **
+  ** The high-order bit of the mask is a "we-use-them-all" bit.
+  ** If the column number is greater than the number of bits in the bitmask
+  ** then set the high-order bit of the bitmask.  Also set the high-order
+  ** bit if the column is a generated column, as that adds dependencies
+  ** that are difficult to track, so we assume that all columns are used.
   */
   if( pExpr->iColumn>=0 && pMatch!=0 ){
     int n = pExpr->iColumn;
@@ -561,7 +570,12 @@
     if( n>=BMS ){
       n = BMS-1;
     }
+    assert( pExpr->y.pTab!=0 );
     assert( pMatch->iCursor==pExpr->iTable );
+    if( pExpr->y.pTab->tabFlags & TF_HasGenerated ){
+      Column *pCol = pExpr->y.pTab->aCol + pExpr->iColumn;
+      if( pCol->colFlags & COLFLAG_GENERATED ) n = BMS-1;
+    }
     pMatch->colUsed |= ((Bitmask)1)<<n;
   }
 
```
