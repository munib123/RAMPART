# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4152_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4152_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 1-39 of the vulnerable file.

/* Copyright 2015 The TensorFlow Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

// See docs in ../ops/data_flow_ops.cc.

#include <limits.h>
#include <vector>

#include "tensorflow/core/common_runtime/device.h"
#include "tensorflow/core/framework/device_base.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/lib/gtl/map_util.h"
#include "tensorflow/core/platform/logging.h"
#include "tensorflow/core/platform/macros.h"
#include "tensorflow/core/platform/mutex.h"
#include "tensorflow/core/platform/thread_annotations.h"
#include "tensorflow/core/platform/types.h"

namespace tensorflow {

class GetSessionHandleOp : public OpKernel {
 public:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 // See docs in ../ops/data_flow_ops.cc.
 
 #include <limits.h>
+
 #include <vector>
 
 #include "tensorflow/core/common_runtime/device.h"
@@ -27,6 +28,7 @@
 #include "tensorflow/core/framework/types.h"
 #include "tensorflow/core/lib/core/errors.h"
 #include "tensorflow/core/lib/gtl/map_util.h"
+#include "tensorflow/core/platform/errors.h"
 #include "tensorflow/core/platform/logging.h"
 #include "tensorflow/core/platform/macros.h"
 #include "tensorflow/core/platform/mutex.h"
@@ -42,7 +44,11 @@
 
   void Compute(OpKernelContext* ctx) override {
     const Tensor& val = ctx->input(0);
-    int64 id = ctx->session_state()->GetNewId();
+    auto session_state = ctx->session_state();
+    OP_REQUIRES(ctx, session_state != nullptr,
+                errors::FailedPrecondition(
+                    "GetSessionHandle called on null session state"));
+    int64 id = session_state->GetNewId();
     TensorStore::TensorAndKey tk{val, id, requested_device()};
     OP_REQUIRES_OK(ctx, ctx->tensor_store()->AddTensor(name(), tk));
 
```
