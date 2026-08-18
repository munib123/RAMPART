# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4256_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 332-372 of the vulnerable file.

  // between originalName (which must be valid) and the variable identified by
  // closureAlias.
  Variable *parentVar = nullptr;
  if (lazyData->closureAlias.isValid()) {
    assert(lazyData->originalName.isValid() && "Original name invalid");
    assert(
        lazyData->originalName != lazyData->closureAlias &&
        "Original name must be different from the alias");

    // NOTE: the closureAlias target must exist and must be a Variable.
    parentVar = cast<Variable>(nameTable_.lookup(lazyData->closureAlias));

    // Re-create the alias.
    nameTable_.insert(lazyData->originalName, parentVar);
  }

  assert(
      !llvh::isa<ESTree::ArrowFunctionExpressionNode>(node) &&
      "lazy compilation not supported for arrow functions");

  auto *func = genES5Function(lazyData->originalName, parentVar, node);
  addLexicalDebugInfo(func, topLevel, lexicalScopeChain);
  return {func, topLevel};
}

std::pair<Value *, bool> ESTreeIRGen::declareVariableOrGlobalProperty(
    Function *inFunc,
    VarDecl::Kind declKind,
    Identifier name) {
  Value *found = nameTable_.lookup(name);

  // If the variable is already declared in this scope, do not create a
  // second instance.
  if (found) {
    if (auto *var = llvh::dyn_cast<Variable>(found)) {
      if (var->getParent()->getFunction() == inFunc)
        return {found, false};
    } else {
      assert(
          llvh::isa<GlobalObjectProperty>(found) &&
          "Invalid value found in name table");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -349,7 +349,11 @@
       !llvh::isa<ESTree::ArrowFunctionExpressionNode>(node) &&
       "lazy compilation not supported for arrow functions");
 
-  auto *func = genES5Function(lazyData->originalName, parentVar, node);
+  auto *func = genES5Function(
+      lazyData->originalName,
+      parentVar,
+      node,
+      lazyData->isGeneratorInnerFunction);
   addLexicalDebugInfo(func, topLevel, lexicalScopeChain);
   return {func, topLevel};
 }
```
