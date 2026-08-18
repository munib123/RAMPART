# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 2486_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2486_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 5181-5221 of the vulnerable file.

            {
                if (paramScope->GetCanMergeWithBodyScope())
                {
                    paramScope->ForEachSymbolUntil([this, paramScope, pnodeFnc](Symbol* sym) {
                        if (sym->GetPid()->GetTopRef()->GetFuncScopeId() > pnodeFnc->sxFnc.functionId)
                        {
                            // One of the symbol has non local reference. Mark the param scope as we can't merge it with body scope.
                            paramScope->SetCannotMergeWithBodyScope();
                            return true;
                        }
                        return false;
                    });

                    if (wellKnownPropertyPids.arguments->GetTopRef() && wellKnownPropertyPids.arguments->GetTopRef()->GetFuncScopeId() > pnodeFnc->sxFnc.functionId)
                    {
                        Assert(pnodeFnc->sxFnc.UsesArguments());
                        // Arguments symbol is captured in the param scope
                        paramScope->SetCannotMergeWithBodyScope();
                    }
                }
            }
        }

        if (!fLambda && paramScope != nullptr && !paramScope->GetCanMergeWithBodyScope()
            && (pnodeFnc->sxFnc.UsesArguments() || pnodeFnc->grfpn & fpnArguments_overriddenByDecl))
        {
            Error(ERRNonSimpleParamListArgumentsUse);
        }

        // If the param scope is merged with the body scope we want to use the param scope symbols in the body scope.
        // So add a pid ref for the body using the param scope symbol. Note that in this case the same symbol will occur twice
        // in the same pid ref stack.
        if (paramScope != nullptr && paramScope->GetCanMergeWithBodyScope())
        {
            paramScope->ForEachSymbol([this](Symbol* paramSym)
            {
                PidRefStack* ref = PushPidRef(paramSym->GetPid());
                ref->SetSym(paramSym);
            });
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5198,6 +5198,19 @@
                         paramScope->SetCannotMergeWithBodyScope();
                     }
                 }
+                if (paramScope->GetCanMergeWithBodyScope() && !fDeclaration && pnodeFnc->sxFnc.pnodeName != nullptr)
+                {
+                    Symbol* funcSym = pnodeFnc->sxFnc.pnodeName->sxVar.sym;
+                    if (funcSym->GetPid()->GetTopRef()->GetFuncScopeId() > pnodeFnc->sxFnc.functionId)
+                    {
+                        // This is a function expression with name captured in the param scope. In non-eval, non-split cases the function
+                        // name symbol is added to the body scope to make it accessible in the body. But if there is a function or var
+                        // declaration with the same name in the body then adding to the body will fail. So in this case we have to add
+                        // the name symbol to the param scope by splitting it.
+                        paramScope->SetCannotMergeWithBodyScope();
+                    }
+                }
+
             }
         }
 
```
