# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 2485_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2485_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 2846-2886 of the vulnerable file.


    return pnode;
}

/***************************************************************************
Parse an expression term.
***************************************************************************/
template<bool buildAST>
ParseNodePtr Parser::ParseTerm(BOOL fAllowCall,
    LPCOLESTR pNameHint,
    uint32 *pHintLength,
    uint32 *pShortNameOffset,
    _Inout_opt_ IdentToken* pToken /*= nullptr*/,
    bool fUnaryOrParen /*= false*/,
    _Out_opt_ BOOL* pfCanAssign /*= nullptr*/,
    _Inout_opt_ BOOL* pfLikelyPattern /*= nullptr*/,
    _Out_opt_ bool* pfIsDotOrIndex /*= nullptr*/,
    _Inout_opt_ charcount_t *plastRParen /*= nullptr*/)
{
    ParseNodePtr pnode = nullptr;
    charcount_t ichMin = 0;
    size_t iecpMin = 0;
    size_t iuMin;
    IdentToken term;
    BOOL fInNew = FALSE;
    BOOL fCanAssign = TRUE;
    bool isAsyncExpr = false;
    bool isLambdaExpr = false;
    Assert(pToken == nullptr || pToken->tk == tkNone); // Must be empty initially

    if (this->IsBackgroundParser())
    {
        PROBE_STACK_NO_DISPOSE(m_scriptContext, Js::Constants::MinStackParseOneTerm);
    }
    else
    {
        PROBE_STACK(m_scriptContext, Js::Constants::MinStackParseOneTerm);
    }

    switch (m_token.tk)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2863,6 +2863,7 @@
     _Inout_opt_ charcount_t *plastRParen /*= nullptr*/)
 {
     ParseNodePtr pnode = nullptr;
+    PidRefStack *savedTopAsyncRef = nullptr;
     charcount_t ichMin = 0;
     size_t iecpMin = 0;
     size_t iuMin;
@@ -2915,6 +2916,13 @@
                 isLambdaExpr = true;
                 goto LFunction;
             }
+            else if (m_token.tk == tkLParen)
+            {
+                // This is potentially an async arrow function. Save the state of the async references
+                // in case it needs to be restored. (Note that the case of a single parameter with no ()'s
+                // is detected upstream and need not be handled here.)
+                savedTopAsyncRef = pid->GetTopRef();
+            }
         }
 
         // Don't push a reference if this is a single lambda parameter, because we'll reparse with
@@ -3268,6 +3276,18 @@
     }
 
     pnode = ParsePostfixOperators<buildAST>(pnode, fAllowCall, fInNew, isAsyncExpr, &fCanAssign, &term, pfIsDotOrIndex);
+
+    if (savedTopAsyncRef != nullptr &&
+        this->m_token.tk == tkDArrow)
+    {
+        // This is an async arrow function; we're going to back up and reparse it.
+        // Make sure we don't leave behind a bogus reference to the 'async' identifier.
+        for (IdentPtr pid = wellKnownPropertyPids.async; pid->GetTopRef() != savedTopAsyncRef;)
+        {
+            Assert(pid->GetTopRef() != nullptr);
+            pid->RemovePrevPidRef(nullptr);
+        }
+    }
 
     // Pass back identifier if requested
     if (pToken && term.tk == tkID)
```
