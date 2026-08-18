# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4256_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 261-301 of the vulnerable file.

    if (F->getParent()
            ->shareContext()
            ->allowFunctionToStringWithRuntimeSource() ||
        F->isLazy()) {
      auto context = F->getParent()->shareContext();
      assert(
          (!contextIfNeeded || contextIfNeeded.get() == context.get()) &&
          "Different instances of Context seen");
      contextIfNeeded = context;
      BM->setFunctionSourceRange(i, F->getSourceRange());
    }
#endif

    if (F->isLazy()) {
#ifdef HERMESVM_LEAN
      llvm_unreachable("Lazy support compiled out");
#else
      auto lazyData = llvh::make_unique<LazyCompilationData>();
      lazyData->parentScope = F->getLazyScope();
      lazyData->nodeKind = F->getLazySource().nodeKind;
      lazyData->bufferId = F->getLazySource().bufferId;
      lazyData->originalName = F->getOriginalOrInferredName();
      lazyData->closureAlias = F->getLazyClosureAlias()
          ? F->getLazyClosureAlias()->getName()
          : Identifier();
      lazyData->strictMode = F->isStrictMode();
      func->setLazyCompilationData(std::move(lazyData));
#endif
    }

    if (BFG.hasDebugInfo()) {
      uint32_t sourceLocOffset = debugInfoGen.appendSourceLocations(
          BFG.getSourceLocation(), i, BFG.getDebugLocations());
      uint32_t lexicalDataOffset = debugInfoGen.appendLexicalData(
          BFG.getLexicalParentID(), BFG.getDebugVariableNames());
      func->setDebugOffsets({sourceLocOffset, lexicalDataOffset});
    }
    BM->setFunction(i, std::move(func));
  }

  BM->setContext(contextIfNeeded);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -278,6 +278,8 @@
       auto lazyData = llvh::make_unique<LazyCompilationData>();
       lazyData->parentScope = F->getLazyScope();
       lazyData->nodeKind = F->getLazySource().nodeKind;
+      lazyData->isGeneratorInnerFunction =
+          F->getLazySource().isGeneratorInnerFunction;
       lazyData->bufferId = F->getLazySource().bufferId;
       lazyData->originalName = F->getOriginalOrInferredName();
       lazyData->closureAlias = F->getLazyClosureAlias()
```
