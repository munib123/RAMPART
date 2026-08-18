# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4161_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4161_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/
#ifndef TENSORFLOW_LITE_KERNELS_KERNEL_UTIL_H_
#define TENSORFLOW_LITE_KERNELS_KERNEL_UTIL_H_

#include <stdint.h>

#include <limits>

#include "tensorflow/lite/c/builtin_op_data.h"
#include "tensorflow/lite/c/common.h"

namespace tflite {

// A fair number of functions in this header have historically been inline.
// It is ok to change functions to not be inline if the latency with
// benchmark_model for MobileNet + MobileBERT is unaffected. If such a change is
// made, move the newly non-inlined function declarations to the top of this
// header file.
const TfLiteTensor* GetInput(const TfLiteContext* context,
                             const TfLiteNode* node, int index);

// Note: You must check if result is not null:
// TfLiteTensor* my_tensor = GetVariableInput(context, node, kMyTensorIdx);
// TF_LITE_ENSURE(context, my_tensor != nullptr);
TfLiteTensor* GetVariableInput(TfLiteContext* context, const TfLiteNode* node,
                               int index);

TfLiteTensor* GetOutput(TfLiteContext* context, const TfLiteNode* node,
                        int index);

const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
                                           const TfLiteNode* node, int index);

inline int NumDimensions(const TfLiteTensor* t) { return t->dims->size; }
inline int SizeOfDimension(const TfLiteTensor* t, int dim) {
  return t->dims->data[dim];
}

#ifndef TF_LITE_STATIC_MEMORY
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,18 +29,46 @@
 // benchmark_model for MobileNet + MobileBERT is unaffected. If such a change is
 // made, move the newly non-inlined function declarations to the top of this
 // header file.
+
+// Note: You must check if result is not null:
+//
+//   TfLiteTensor* my_tensor = GetInput(context, node, kMyTensorIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
 const TfLiteTensor* GetInput(const TfLiteContext* context,
                              const TfLiteNode* node, int index);
 
 // Note: You must check if result is not null:
-// TfLiteTensor* my_tensor = GetVariableInput(context, node, kMyTensorIdx);
-// TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+//   TfLiteTensor* my_tensor = GetVariableInput(context, node, kMyTensorIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
 TfLiteTensor* GetVariableInput(TfLiteContext* context, const TfLiteNode* node,
                                int index);
 
+// Note: You must check if result is not null:
+//
+//   TfLiteTensor* my_tensor = GetOutput(context, node, kMyTensorIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
 TfLiteTensor* GetOutput(TfLiteContext* context, const TfLiteNode* node,
                         int index);
 
+// Note: You must check if result is not null:
+//
+//   TfLiteTensor* my_tensor = GetOptionalInputTensor(context, node, kIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
+//
+// Deprecated. GetInput has the same functionality.
 const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
                                            const TfLiteNode* node, int index);
 
@@ -50,14 +78,46 @@
 }
 
 #ifndef TF_LITE_STATIC_MEMORY
+// Note: You must check if result is not null:
+//
+//   TfLiteTensor* my_tensor = GetTemporary(context, node, kMyTensorIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
 inline TfLiteTensor* GetTemporary(TfLiteContext* context,
                                   const TfLiteNode* node, int index) {
-  return &context->tensors[node->temporaries->data[index]];
-}
+  if (index >= 0 && index < node->temporaries->size) {
+    const int tensor_index = node->temporaries->data[index];
+    if (tensor_index != kTfLiteOptionalTensor) {
+      if (context->tensors != nullptr) {
+        return &context->tensors[tensor_index];
+      }
+    }
+  }
+  return nullptr;
+}
+
+// Note: You must check if result is not null:
+//
+//   TfLiteTensor* my_tensor = GetIntermediates(context, node, kMyTensorIdx);
+//   TF_LITE_ENSURE(context, my_tensor != nullptr);
+//
+// This is because the index might point to the optional tensor constant
+// (kTfLiteOptionalTensor) in which case there is no tensor to return.
 inline const TfLiteTensor* GetIntermediates(TfLiteContext* context,
                                             const TfLiteNode* node, int index) {
-  return &context->tensors[node->intermediates->data[index]];
-}
+  if (index >= 0 && index < node->intermediates->size) {
+    const int tensor_index = node->intermediates->data[index];
+    if (tensor_index != kTfLiteOptionalTensor) {
+      if (context->tensors != nullptr) {
+        return &context->tensors[tensor_index];
+      }
+    }
+  }
+  return nullptr;
+}
+
 inline int NumIntermediates(const TfLiteNode* node) {
   return node->intermediates->size;
 }
```
