# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in c
**Pair ID:** 4258_0
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4258_0`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```c
Lines 19-59 of the vulnerable file.

/// needs access to the private fields of Runtime, but doesn't belong in
/// Runtime.
class Interpreter {
 public:
  /// Allocate a GeneratorFuncxtion for the specified function and the specified
  /// environment. \param funcIndex function index in the global function table.
  static CallResult<PseudoHandle<JSGeneratorFunction>> createGeneratorClosure(
      Runtime *runtime,
      RuntimeModule *runtimeModule,
      unsigned funcIndex,
      Handle<Environment> envHandle);

  /// Allocate a generator for the specified function and the specified
  /// environment. \param funcIndex function index in the global function table.
  static CallResult<PseudoHandle<JSGenerator>> createGenerator_RJS(
      Runtime *runtime,
      RuntimeModule *runtimeModule,
      unsigned funcIndex,
      Handle<Environment> envHandle,
      NativeArgs args);

  /// Slow path for ReifyArguments resReg, lazyReg
  /// It assumes that he fast path has handled the case when 'lazyReg' is
  /// already initialized. It creates a new 'arguments' object and populates it
  /// with the argument values.
  static CallResult<Handle<Arguments>> reifyArgumentsSlowPath(
      Runtime *runtime,
      Handle<Callable> curFunction,
      bool strictMode);

  /// Slow path for GetArgumentsPropByVal resReg, propNameReg, lazyReg.
  ///
  /// It assumes that the "fast path" has already taken care of the case when
  /// the 'lazyReg' is still uninitialized and 'propNameReg' is a valid integer
  /// index less than 'argCount'. So we arrive here when either of these is
  /// true:
  /// - 'lazyReg' is initialized.
  /// - index is >= argCount
  /// - index is not an integer
  /// In the first case we simply perform a normal property get. In the latter
  /// we ultimately need to reify the arguments object, but we try to avoid
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,14 @@
       unsigned funcIndex,
       Handle<Environment> envHandle,
       NativeArgs args);
+
+  /// Suspend the generator function and yield to the caller.
+  /// \param resumeIP Is the IP where the generator should resume from when it
+  ///   is resumed.
+  static void saveGenerator(
+      Runtime *runtime,
+      PinnedHermesValue *frameRegs,
+      const Inst *resumeIP);
 
   /// Slow path for ReifyArguments resReg, lazyReg
   /// It assumes that he fast path has handled the case when 'lazyReg' is
```
