# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1327_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1327_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2792-2832 of the vulnerable file.

        sqlite3VdbeAddOp4Int(v, OP_NotFound, tab2, iCont, r1, 0);
        VdbeCoverage(v);
        sqlite3ReleaseTempReg(pParse, r1);
        selectInnerLoop(pParse, p, tab1,
                        0, 0, &dest, iCont, iBreak);
        sqlite3VdbeResolveLabel(v, iCont);
        sqlite3VdbeAddOp2(v, OP_Next, tab1, iStart); VdbeCoverage(v);
        sqlite3VdbeResolveLabel(v, iBreak);
        sqlite3VdbeAddOp2(v, OP_Close, tab2, 0);
        sqlite3VdbeAddOp2(v, OP_Close, tab1, 0);
        break;
      }
    }
  
  #ifndef SQLITE_OMIT_EXPLAIN
    if( p->pNext==0 ){
      ExplainQueryPlanPop(pParse);
    }
  #endif
  }
  
  /* Compute collating sequences used by 
  ** temporary tables needed to implement the compound select.
  ** Attach the KeyInfo structure to all temporary tables.
  **
  ** This section is run by the right-most SELECT statement only.
  ** SELECT statements to the left always skip this part.  The right-most
  ** SELECT might also skip this part if it has no ORDER BY clause and
  ** no temp tables are required.
  */
  if( p->selFlags & SF_UsesEphemeral ){
    int i;                        /* Loop counter */
    KeyInfo *pKeyInfo;            /* Collating sequence for the result set */
    Select *pLoop;                /* For looping through SELECT statements */
    CollSeq **apColl;             /* For looping through pKeyInfo->aColl[] */
    int nCol;                     /* Number of columns in result set */

    assert( p->pNext==0 );
    nCol = p->pEList->nExpr;
    pKeyInfo = sqlite3KeyInfoAlloc(db, nCol, 1);
    if( !pKeyInfo ){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2809,6 +2809,7 @@
     }
   #endif
   }
+  if( pParse->nErr ) goto multi_select_end;
   
   /* Compute collating sequences used by 
   ** temporary tables needed to implement the compound select.
```
