# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 1310_4
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1310_4`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 2939-2979 of the vulnerable file.

#define SF_All           0x0000002 /* Includes the ALL keyword */
#define SF_Resolved      0x0000004 /* Identifiers have been resolved */
#define SF_Aggregate     0x0000008 /* Contains agg functions or a GROUP BY */
#define SF_HasAgg        0x0000010 /* Contains aggregate functions */
#define SF_UsesEphemeral 0x0000020 /* Uses the OpenEphemeral opcode */
#define SF_Expanded      0x0000040 /* sqlite3SelectExpand() called on this */
#define SF_HasTypeInfo   0x0000080 /* FROM subqueries have Table metadata */
#define SF_Compound      0x0000100 /* Part of a compound query */
#define SF_Values        0x0000200 /* Synthesized from VALUES clause */
#define SF_MultiValue    0x0000400 /* Single VALUES term with multiple rows */
#define SF_NestedFrom    0x0000800 /* Part of a parenthesized FROM clause */
#define SF_MinMaxAgg     0x0001000 /* Aggregate containing min() or max() */
#define SF_Recursive     0x0002000 /* The recursive part of a recursive CTE */
#define SF_FixedLimit    0x0004000 /* nSelectRow set by a constant LIMIT */
#define SF_MaybeConvert  0x0008000 /* Need convertCompoundSelectToSubquery() */
#define SF_Converted     0x0010000 /* By convertCompoundSelectToSubquery() */
#define SF_IncludeHidden 0x0020000 /* Include hidden columns in output */
#define SF_ComplexResult 0x0040000 /* Result contains subquery or function */
#define SF_WhereBegin    0x0080000 /* Really a WhereBegin() call.  Debug Only */
#define SF_WinRewrite    0x0100000 /* Window function rewrite accomplished */

/*
** The results of a SELECT can be distributed in several ways, as defined
** by one of the following macros.  The "SRT" prefix means "SELECT Result
** Type".
**
**     SRT_Union       Store results as a key in a temporary index
**                     identified by pDest->iSDParm.
**
**     SRT_Except      Remove results from the temporary index pDest->iSDParm.
**
**     SRT_Exists      Store a 1 in memory cell pDest->iSDParm if the result
**                     set is not empty.
**
**     SRT_Discard     Throw the results away.  This is used by SELECT
**                     statements within triggers whose only purpose is
**                     the side-effects of functions.
**
** All of the above are free to ignore their ORDER BY clause. Those that
** follow must honor the ORDER BY clause.
**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2956,6 +2956,7 @@
 #define SF_ComplexResult 0x0040000 /* Result contains subquery or function */
 #define SF_WhereBegin    0x0080000 /* Really a WhereBegin() call.  Debug Only */
 #define SF_WinRewrite    0x0100000 /* Window function rewrite accomplished */
+#define SF_View          0x0200000 /* SELECT statement is a view */
 
 /*
 ** The results of a SELECT can be distributed in several ways, as defined
```
