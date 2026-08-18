# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4160_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4160_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 16-57 of the vulnerable file.


#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/kernels/internal/reference/reference_ops.h"
#include "tensorflow/lite/kernels/internal/tensor.h"
#include "tensorflow/lite/kernels/internal/tensor_ctypes.h"
#include "tensorflow/lite/kernels/kernel_util.h"

namespace tflite {
namespace ops {
namespace builtin {
namespace add_n {

constexpr int kInputTensor1 = 0;
constexpr int kOutputTensor = 0;

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  int num_inputs = NumInputs(node);
  TF_LITE_ENSURE(context, num_inputs >= 2);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
  output->type = input1->type;

  // Check that all input tensors have the same shape and type.
  for (int i = kInputTensor1 + 1; i < num_inputs; ++i) {
    const TfLiteTensor* input = GetInput(context, node, i);
    TF_LITE_ENSURE(context, HaveSameShapes(input1, input));
    TF_LITE_ENSURE_TYPES_EQ(context, input1->type, input->type);
  }

  // Use the first input node's dimension to be the dimension of the output
  // node.
  TfLiteIntArray* input1_dims = input1->dims;
  TfLiteIntArray* output_dims = TfLiteIntArrayCopy(input1_dims);
  return context->ResizeTensor(context, output, output_dims);
}

template <typename T>
void EvalAddN(TfLiteContext* context, TfLiteNode* node) {
  // TODO(haoliang): Initialize all_inputs only once during init.
  VectorOfTensors<T> all_inputs(*context, *node->inputs);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,13 +33,18 @@
   TF_LITE_ENSURE(context, num_inputs >= 2);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
 
-  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
-  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  const TfLiteTensor* input1;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor1, &input1));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context,
+                    GetOutputSafe(context, node, kOutputTensor, &output));
   output->type = input1->type;
 
   // Check that all input tensors have the same shape and type.
   for (int i = kInputTensor1 + 1; i < num_inputs; ++i) {
-    const TfLiteTensor* input = GetInput(context, node, i);
+    const TfLiteTensor* input;
+    TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, i, &input));
     TF_LITE_ENSURE(context, HaveSameShapes(input1, input));
     TF_LITE_ENSURE_TYPES_EQ(context, input1->type, input->type);
   }
@@ -55,15 +60,22 @@
 void EvalAddN(TfLiteContext* context, TfLiteNode* node) {
   // TODO(haoliang): Initialize all_inputs only once during init.
   VectorOfTensors<T> all_inputs(*context, *node->inputs);
+  // Safe to use unchecked since caller checks that tensor is valid
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
   int num_inputs = NumInputs(node);
+  // Safe to use unchecked since caller checks that tensor is valid
   const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
   reference_ops::AddN<T>(GetTensorShape(input1), num_inputs, all_inputs.data(),
                          GetTensorData<T>(output));
 }
 
 TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
-  const TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  const TfLiteTensor* input1;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor1, &input1));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context,
+                    GetOutputSafe(context, node, kOutputTensor, &output));
   if (output->type == kTfLiteFloat32) {
     EvalAddN<float>(context, node);
   } else if (output->type == kTfLiteInt32) {
```
