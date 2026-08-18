# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4157_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4157_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 2-42 of the vulnerable file.


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

#include "tensorflow/lite/core/subgraph.h"

#include <algorithm>
#include <cstdint>

#include "tensorflow/lite/arena_planner.h"
#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/context_util.h"
#include "tensorflow/lite/core/api/tensor_utils.h"
#include "tensorflow/lite/delegates/nnapi/nnapi_delegate.h"
#include "tensorflow/lite/graph_info.h"
#include "tensorflow/lite/minimal_logging.h"
#include "tensorflow/lite/schema/schema_generated.h"
#include "tensorflow/lite/util.h"

namespace tflite {

namespace {

struct TfLiteQuantizationDeleter {
  void operator()(TfLiteQuantization* q) {
    if (q) TfLiteQuantizationFree(q);
  }
};

using ScopedTfLiteQuantization =
    std::unique_ptr<TfLiteQuantization, TfLiteQuantizationDeleter>;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 #include <cstdint>
 
 #include "tensorflow/lite/arena_planner.h"
+#include "tensorflow/lite/builtin_ops.h"
 #include "tensorflow/lite/c/common.h"
 #include "tensorflow/lite/context_util.h"
 #include "tensorflow/lite/core/api/tensor_utils.h"
@@ -1030,6 +1031,19 @@
           tensor->data_is_stale) {
         TF_LITE_ENSURE_STATUS(EnsureTensorDataIsReadable(tensor_index));
       }
+      if (tensor->data.raw == nullptr && tensor->bytes > 0) {
+        if (registration.builtin_code == kTfLiteBuiltinReshape && i == 1) {
+          // In general, having a tensor here with no buffer will be an error.
+          // However, for the reshape operator, the second input tensor is only
+          // used for the shape, not for the data. Thus, null buffer is ok.
+          continue;
+        } else {
+          // In all other cases, we need to return an error as otherwise we will
+          // trigger a null pointer dereference (likely).
+          ReportError("Input tensor %d lacks data", tensor_index);
+          return kTfLiteError;
+        }
+      }
     }
 
     if (check_cancelled_func_ != nullptr &&
```
