# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4161_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4161_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 15-58 of the vulnerable file.

#include "tensorflow/lite/kernels/kernel_util.h"

#include <stdint.h>
#include <stdlib.h>

#include <algorithm>
#include <limits>
#include <memory>

#include "tensorflow/lite/c/builtin_op_data.h"
#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/kernels/internal/cppmath.h"
#include "tensorflow/lite/kernels/internal/quantization_util.h"

namespace tflite {

namespace {

inline TfLiteTensor* GetMutableInput(const TfLiteContext* context,
                                     const TfLiteNode* node, int index) {
  if (context->tensors != nullptr) {
    return &context->tensors[node->inputs->data[index]];
  } else {
    return context->GetTensor(context, node->inputs->data[index]);
  }
}

}  // anonymous namespace.

const TfLiteTensor* GetInput(const TfLiteContext* context,
                             const TfLiteNode* node, int index) {
  return GetMutableInput(context, node, index);
}

TfLiteTensor* GetVariableInput(TfLiteContext* context, const TfLiteNode* node,
                               int index) {
  TfLiteTensor* tensor = GetMutableInput(context, node, index);
  return tensor->is_variable ? tensor : nullptr;
}

TfLiteTensor* GetOutput(TfLiteContext* context, const TfLiteNode* node,
                        int index) {
  if (context->tensors != nullptr) {
    return &context->tensors[node->outputs->data[index]];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,11 +32,17 @@
 
 inline TfLiteTensor* GetMutableInput(const TfLiteContext* context,
                                      const TfLiteNode* node, int index) {
-  if (context->tensors != nullptr) {
-    return &context->tensors[node->inputs->data[index]];
-  } else {
-    return context->GetTensor(context, node->inputs->data[index]);
-  }
+  if (index >= 0 && index < node->inputs->size) {
+    const int tensor_index = node->inputs->data[index];
+    if (tensor_index != kTfLiteOptionalTensor) {
+      if (context->tensors != nullptr) {
+        return &context->tensors[tensor_index];
+      } else {
+        return context->GetTensor(context, tensor_index);
+      }
+    }
+  }
+  return nullptr;
 }
 
 }  // anonymous namespace.
@@ -54,11 +60,17 @@
 
 TfLiteTensor* GetOutput(TfLiteContext* context, const TfLiteNode* node,
                         int index) {
-  if (context->tensors != nullptr) {
-    return &context->tensors[node->outputs->data[index]];
-  } else {
-    return context->GetTensor(context, node->outputs->data[index]);
-  }
+  if (index >= 0 && index < node->outputs->size) {
+    const int tensor_index = node->outputs->data[index];
+    if (tensor_index != kTfLiteOptionalTensor) {
+      if (context->tensors != nullptr) {
+        return &context->tensors[tensor_index];
+      } else {
+        return context->GetTensor(context, tensor_index);
+      }
+    }
+  }
+  return nullptr;
 }
 
 const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
```
