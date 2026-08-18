# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 2486_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2486_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 3302-3342 of the vulnerable file.

        {
            this->InitBlockScopedNonTemps(funcInfo->root->sxFnc.pnodeScopes, funcInfo);
        }

        if (!pnode->sxFnc.HasNonSimpleParameterList() && funcInfo->GetHasArguments() && !NeedScopeObjectForArguments(funcInfo, pnode))
        {
            // If we didn't create a scope object and didn't have default args, we still need to transfer the formals to their slots.
            MapFormalsWithoutRest(pnode, [&](ParseNode *pnodeArg) { EmitPropStore(pnodeArg->sxVar.sym->GetLocation(), pnodeArg->sxVar.sym, pnodeArg->sxVar.pid, funcInfo); });
        }

        // Rest needs to trigger use before declaration until all default args have been processed.
        if (pnode->sxFnc.pnodeRest != nullptr)
        {
            pnode->sxFnc.pnodeRest->sxVar.sym->SetNeedDeclaration(false);
        }

        if (paramScope && !paramScope->GetCanMergeWithBodyScope())
        {
            // Emit bytecode to copy the initial values from param names to their corresponding body bindings.
            // We have to do this after the rest param is marked as false for need declaration.
            paramScope->ForEachSymbol([&](Symbol* param) {
                Symbol* varSym = funcInfo->GetBodyScope()->FindLocalSymbol(param->GetName());
                Assert(varSym || pnode->sxFnc.pnodeName->sxVar.sym == param);
                Assert(param->GetIsArguments() || param->IsInSlot(funcInfo));
                if (param->GetIsArguments() && !funcInfo->GetHasArguments())
                {
                    // Do not copy the arguments to the body if it is not used
                }
                else if (varSym && varSym->GetSymbolType() == STVariable && (varSym->IsInSlot(funcInfo) || varSym->GetLocation() != Js::Constants::NoRegister))
                {
                    // Simulating EmitPropLoad here. We can't directly call the method as we have to use the param scope specifically.
                    // Walking the scope chain is not possible at this time.
                    Js::RegSlot tempReg = funcInfo->AcquireTmpRegister();
                    Js::PropertyId slot = param->EnsureScopeSlot(funcInfo);
                    Js::ProfileId profileId = funcInfo->FindOrAddSlotProfileId(paramScope, slot);
                    Js::OpCode op = paramScope->GetIsObject() ? Js::OpCode::LdParamObjSlot : Js::OpCode::LdParamSlot;
                    slot = slot + (paramScope->GetIsObject() ? 0 : Js::ScopeSlots::FirstSlotIndex);

                    this->m_writer.SlotI1(op, tempReg, slot, profileId);

                    if (ShouldTrackDebuggerMetadata() && !varSym->GetIsArguments() && !varSym->IsInSlot(funcInfo))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3319,6 +3319,7 @@
         {
             // Emit bytecode to copy the initial values from param names to their corresponding body bindings.
             // We have to do this after the rest param is marked as false for need declaration.
+            Symbol* funcSym = funcInfo->root->sxFnc.GetFuncSymbol();
             paramScope->ForEachSymbol([&](Symbol* param) {
                 Symbol* varSym = funcInfo->GetBodyScope()->FindLocalSymbol(param->GetName());
                 Assert(varSym || pnode->sxFnc.pnodeName->sxVar.sym == param);
@@ -3327,7 +3328,9 @@
                 {
                     // Do not copy the arguments to the body if it is not used
                 }
-                else if (varSym && varSym->GetSymbolType() == STVariable && (varSym->IsInSlot(funcInfo) || varSym->GetLocation() != Js::Constants::NoRegister))
+                else if ((funcSym == nullptr || funcSym != param)    // Do not copy the symbol over to body as the function expression symbol
+                                                                     // is expected to stay inside the function expression scope
+                    && (varSym && varSym->GetSymbolType() == STVariable && (varSym->IsInSlot(funcInfo) || varSym->GetLocation() != Js::Constants::NoRegister)))
                 {
                     // Simulating EmitPropLoad here. We can't directly call the method as we have to use the param scope specifically.
                     // Walking the scope chain is not possible at this time.
```
