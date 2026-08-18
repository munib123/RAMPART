# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4256_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4256_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 319-359 of the vulnerable file.

/// should be captured from a function two levels down the lexical stack.
class SerializedScope {
 public:
  /// Parent scope, if any.
  std::shared_ptr<const SerializedScope> parentScope;
  /// Original name of the function, if any.
  Identifier originalName;
  /// The generated name of the variable holding the function in the parent's
  /// frame, which is what we need to look up to reference ourselves. It is only
  /// set if there is an alias binding from \c originalName (which must be
  /// valid) and said variable, which must have a different name (since it is
  /// generated). Function::lazyClosureAlias_.
  Identifier closureAlias;
  /// List of variable names in the frame.
  llvh::SmallVector<Identifier, 16> variables;
};

#ifndef HERMESVM_LEAN
/// The source of a lazy AST node.
struct LazySource {
  // The type of node (such as a FunctionDeclaration or FunctionExpression).
  ESTree::NodeKind nodeKind{ESTree::NodeKind::Empty};
  /// The source buffer id in which this function can be find.
  uint32_t bufferId{0};
  /// The range of the function within the buffer (the whole function node, not
  /// just the lazily parsed body).
  SMRange functionRange;
};
#endif

class Value {
 public:
  using UseListTy = llvh::SmallVector<Instruction *, 2>;
  using Use = std::pair<Value *, unsigned>;

 private:
  // We declare operator delete as a private member below. Classes declared
  // as friend below invokes constructor of Value subtypes directly.
  // C++ requires that if an exception is raised during construction of
  // a new object, the object is deleted.
  // As a result, delete must be accessible to callers of constructors.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -336,8 +336,10 @@
 #ifndef HERMESVM_LEAN
 /// The source of a lazy AST node.
 struct LazySource {
-  // The type of node (such as a FunctionDeclaration or FunctionExpression).
+  /// The type of node (such as a FunctionDeclaration or FunctionExpression).
   ESTree::NodeKind nodeKind{ESTree::NodeKind::Empty};
+  /// Whether or not this is the inner function of a generator
+  bool isGeneratorInnerFunction;
   /// The source buffer id in which this function can be find.
   uint32_t bufferId{0};
   /// The range of the function within the buffer (the whole function node, not
```
