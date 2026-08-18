# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4256_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.


struct LazyCompilationData {
  /// The variables in scope at the point where the function is defined.
  std::shared_ptr<SerializedScope> parentScope;

  /// The original name of the function, as found in the source.
  Identifier originalName;
  /// The generated name of the variable holding the function in the parent's
  /// frame, which is what we need to look up to reference ourselves. It is only
  /// set if there is an alias binding from \c originalName (which must be
  /// valid) and said variable, which must have a different name (since it is
  /// generated). Function::lazyClosureAlias_.
  Identifier closureAlias;

  /// The source buffer ID in which we can find the function source.
  uint32_t bufferId;

  /// The type of function, e.g. statement or expression.
  ESTree::NodeKind nodeKind;

  /// Whether or not the function is strict.
  bool strictMode;
};
} // namespace hbc

/// Lowers an ESTree program into Hermes IR in \p M.
/// \param declFileList a list of parsed global property definition files.
/// \param scopeChain identifiers in the environment, if compiling for local
/// eval. \returns True if an error occured and a message was emitted.
bool generateIRFromESTree(
    ESTree::NodePtr node,
    Module *M,
    const DeclarationFileListTy &declFileList,
    const ScopeChain &scopeChain);

/// Lowers an ESTree program into Hermes IR in \p M without a top-level
/// function, so that it can be used as a CommonJS module.
/// \param id the ID assigned to the CommonJS module when added to the IR
///           (index when reading filenames for the first time)
/// \param filename the relative filename to the CommonJS module.
void generateIRForCJSModule(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,9 @@
   /// The type of function, e.g. statement or expression.
   ESTree::NodeKind nodeKind;
 
+  /// Whether or not this is the inner function of a generator.
+  bool isGeneratorInnerFunction;
+
   /// Whether or not the function is strict.
   bool strictMode;
 };
```
