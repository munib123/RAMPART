# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4256_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 198-238 of the vulnerable file.

            ESTree::isStrict(functionNode->strictness),
            functionNode->getSourceRange(),
            /* insertBefore */ nullptr)
      : Builder.createFunction(
            originalName,
            Function::DefinitionKind::ES5Function,
            ESTree::isStrict(functionNode->strictness),
            functionNode->getSourceRange(),
            /* isGlobal */ false,
            /* insertBefore */ nullptr);

  newFunction->setLazyClosureAlias(lazyClosureAlias);

  if (auto *bodyBlock = llvh::dyn_cast<ESTree::BlockStatementNode>(body)) {
    if (bodyBlock->isLazyFunctionBody) {
      // Set the AST position and variable context so we can continue later.
      newFunction->setLazyScope(saveCurrentScope());
      auto &lazySource = newFunction->getLazySource();
      lazySource.bufferId = bodyBlock->bufferId;
      lazySource.nodeKind = getLazyFunctionKind(functionNode);
      lazySource.functionRange = functionNode->getSourceRange();

      // Set the function's .length.
      newFunction->setExpectedParamCountIncludingThis(
          countExpectedArgumentsIncludingThis(functionNode));
      return newFunction;
    }
  }

  FunctionContext newFunctionContext{
      this, newFunction, functionNode->getSemInfo()};

  if (isGeneratorInnerFunction) {
    // StartGeneratorInst
    // ResumeGeneratorInst
    // at the beginning of the function, to allow for the first .next() call.
    auto *initGenBB = Builder.createBasicBlock(newFunction);
    Builder.setInsertionBlock(initGenBB);
    Builder.createStartGeneratorInst();
    auto *prologueBB = Builder.createBasicBlock(newFunction);
    auto *prologueResumeIsReturn = Builder.createAllocStackInst(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -215,6 +215,7 @@
       auto &lazySource = newFunction->getLazySource();
       lazySource.bufferId = bodyBlock->bufferId;
       lazySource.nodeKind = getLazyFunctionKind(functionNode);
+      lazySource.isGeneratorInnerFunction = isGeneratorInnerFunction;
       lazySource.functionRange = functionNode->getSourceRange();
 
       // Set the function's .length.
@@ -302,14 +303,17 @@
       ESTree::isStrict(functionNode->strictness),
       /* insertBefore */ nullptr);
 
-  auto *innerFn = genES5Function(
-      genAnonymousLabelName(originalName.isValid() ? originalName.str() : ""),
-      lazyClosureAlias,
-      functionNode,
-      true);
-
   {
     FunctionContext outerFnContext{this, outerFn, functionNode->getSemInfo()};
+
+    // Build the inner function. This must be done in the outerFnContext
+    // since it's lexically considered a child function.
+    auto *innerFn = genES5Function(
+        genAnonymousLabelName(originalName.isValid() ? originalName.str() : ""),
+        lazyClosureAlias,
+        functionNode,
+        true);
+
     emitFunctionPrologue(
         functionNode,
         Builder.createBasicBlock(outerFn),
```
