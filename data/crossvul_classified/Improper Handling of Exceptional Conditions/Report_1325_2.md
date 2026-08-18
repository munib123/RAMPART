# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in c
**Pair ID:** 1325_2
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1325_2`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```c
Lines 359-399 of the vulnerable file.

  }
}

/*
** Generate code for a comparison operator.
*/
static int codeCompare(
  Parse *pParse,    /* The parsing (and code generating) context */
  Expr *pLeft,      /* The left operand */
  Expr *pRight,     /* The right operand */
  int opcode,       /* The comparison opcode */
  int in1, int in2, /* Register holding operands */
  int dest,         /* Jump here if true.  */
  int jumpIfNull,   /* If true, jump if either operand is NULL */
  int isCommuted    /* The comparison has been commuted */
){
  int p5;
  int addr;
  CollSeq *p4;

  if( isCommuted ){
    p4 = sqlite3BinaryCompareCollSeq(pParse, pRight, pLeft);
  }else{
    p4 = sqlite3BinaryCompareCollSeq(pParse, pLeft, pRight);
  }
  p5 = binaryCompareP5(pLeft, pRight, jumpIfNull);
  addr = sqlite3VdbeAddOp4(pParse->pVdbe, opcode, in2, dest, in1,
                           (void*)p4, P4_COLLSEQ);
  sqlite3VdbeChangeP5(pParse->pVdbe, (u8)p5);
  return addr;
}

/*
** Return true if expression pExpr is a vector, or false otherwise.
**
** A vector is defined as any expression that results in two or more
** columns of result.  Every TK_VECTOR node is an vector because the
** parser will not generate a TK_VECTOR with fewer than two entries.
** But a TK_SELECT might be either a vector or a scalar. It is only
** considered a vector if it has two or more result columns.
*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -376,6 +376,7 @@
   int addr;
   CollSeq *p4;
 
+  if( pParse->nErr ) return 0;
   if( isCommuted ){
     p4 = sqlite3BinaryCompareCollSeq(pParse, pRight, pLeft);
   }else{
```
