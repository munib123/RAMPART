# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 1311_2
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1311_2`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 607-647 of the vulnerable file.

    for(;;){
      assert( pTopNC!=0 );
      pTopNC->nRef++;
      if( pTopNC==pNC ) break;
      pTopNC = pTopNC->pNext;
    }
    return WRC_Prune;
  } else {
    return WRC_Abort;
  }
}

/*
** Allocate and return a pointer to an expression to load the column iCol
** from datasource iSrc in SrcList pSrc.
*/
Expr *sqlite3CreateColumnExpr(sqlite3 *db, SrcList *pSrc, int iSrc, int iCol){
  Expr *p = sqlite3ExprAlloc(db, TK_COLUMN, 0, 0);
  if( p ){
    struct SrcList_item *pItem = &pSrc->a[iSrc];
    p->y.pTab = pItem->pTab;
    p->iTable = pItem->iCursor;
    if( p->y.pTab->iPKey==iCol ){
      p->iColumn = -1;
    }else{
      p->iColumn = (ynVar)iCol;
      testcase( iCol==BMS );
      testcase( iCol==BMS-1 );
      pItem->colUsed |= ((Bitmask)1)<<(iCol>=BMS ? BMS-1 : iCol);
    }
  }
  return p;
}

/*
** Report an error that an expression is not valid for some set of
** pNC->ncFlags values determined by validMask.
*/
static void notValid(
  Parse *pParse,       /* Leave error message here */
  NameContext *pNC,    /* The name context */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -624,15 +624,28 @@
   Expr *p = sqlite3ExprAlloc(db, TK_COLUMN, 0, 0);
   if( p ){
     struct SrcList_item *pItem = &pSrc->a[iSrc];
-    p->y.pTab = pItem->pTab;
+    Table *pTab = p->y.pTab = pItem->pTab;
     p->iTable = pItem->iCursor;
     if( p->y.pTab->iPKey==iCol ){
       p->iColumn = -1;
     }else{
       p->iColumn = (ynVar)iCol;
-      testcase( iCol==BMS );
-      testcase( iCol==BMS-1 );
-      pItem->colUsed |= ((Bitmask)1)<<(iCol>=BMS ? BMS-1 : iCol);
+      if( pTab->tabFlags & TF_HasGenerated ){
+        Column *pColumn = pTab->aCol + iCol;
+        if( pColumn->colFlags & COLFLAG_GENERATED ){
+          testcase( pTab->nCol==63 );
+          testcase( pTab->nCol==64 );
+          if( pTab->nCol>=64 ){
+            pItem->colUsed = ALLBITS;
+          }else{
+            pItem->colUsed = MASKBIT(pTab->nCol)-1;
+          }
+        }
+      }else{
+        testcase( iCol==BMS );
+        testcase( iCol==BMS-1 );
+        pItem->colUsed |= ((Bitmask)1)<<(iCol>=BMS ? BMS-1 : iCol);
+      }
     }
   }
   return p;
```
