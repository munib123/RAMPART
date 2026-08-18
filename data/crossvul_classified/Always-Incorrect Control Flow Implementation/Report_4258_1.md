# CrossVul Fix Pair: Always-Incorrect Control Flow Implementation in cpp
**Pair ID:** 4258_1
**Vulnerability Class:** Always-Incorrect Control Flow Implementation
**CWE:** CWE-670
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4258_1`)

## Vulnerability Information & PoC

## Description
Always-Incorrect Control Flow Implementation - This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing.

## Vulnerable Code
```cpp
Lines 1-32 of the vulnerable file.

/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define DEBUG_TYPE "vm"
#include "JSLib/JSLibInternal.h"
#include "hermes/VM/Casting.h"
#include "hermes/VM/Interpreter.h"
#include "hermes/VM/StringPrimitive.h"

#include "Interpreter-internal.h"

using namespace hermes::inst;

namespace hermes {
namespace vm {

ExecutionStatus Interpreter::caseDirectEval(
    Runtime *runtime,
    PinnedHermesValue *frameRegs,
    const Inst *ip) {
  auto *result = &O1REG(DirectEval);
  auto *input = &O2REG(DirectEval);

  GCScopeMarkerRAII gcMarker{runtime};

  // Check to see if global eval() has been overriden, in which case call it as
  // as normal function.
  auto global = runtime->getGlobal();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 #include "JSLib/JSLibInternal.h"
 #include "hermes/VM/Casting.h"
 #include "hermes/VM/Interpreter.h"
+#include "hermes/VM/StackFrame-inline.h"
 #include "hermes/VM/StringPrimitive.h"
 
 #include "Interpreter-internal.h"
@@ -17,6 +18,16 @@
 
 namespace hermes {
 namespace vm {
+
+void Interpreter::saveGenerator(
+    Runtime *runtime,
+    PinnedHermesValue *frameRegs,
+    const Inst *resumeIP) {
+  auto *innerFn = vmcast<GeneratorInnerFunction>(FRAME.getCalleeClosure());
+  innerFn->saveStack(runtime);
+  innerFn->setNextIP(resumeIP);
+  innerFn->setState(GeneratorInnerFunction::State::SuspendedYield);
+}
 
 ExecutionStatus Interpreter::caseDirectEval(
     Runtime *runtime,
```
