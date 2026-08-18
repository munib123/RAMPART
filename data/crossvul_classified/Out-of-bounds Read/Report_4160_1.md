# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4160_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4160_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 74-116 of the vulnerable file.

  // It is used in 16-bit -> 16-bit quantization.
  bool pot_scale_int16;
};

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  auto* data = new OpData;
  return data;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteAddParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
  const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);

  TF_LITE_ENSURE_TYPES_EQ(context, input1->type, input2->type);
  output->type = input2->type;

  const bool requires_broadcast = !HaveSameShapes(input1, input2);

  TfLiteIntArray* output_size = nullptr;
  if (requires_broadcast) {
    TF_LITE_ENSURE_OK(context, CalculateShapeForBroadcast(
                                   context, input1, input2, &output_size));
  } else {
    output_size = TfLiteIntArrayCopy(input1->dims);
  }

  // 8bit -> 8bit general quantized path, with general rescalings
  // as well as, int16 -> int16 with general rescalings
  bool pot_scale_int16 = true;

  bool input1_scale_is_pot = false;
  bool input2_scale_is_pot = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,9 +91,15 @@
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
 
-  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
-  const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
-  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  const TfLiteTensor* input1;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor1, &input1));
+  const TfLiteTensor* input2;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor2, &input2));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context,
+                    GetOutputSafe(context, node, kOutputTensor, &output));
 
   TF_LITE_ENSURE_TYPES_EQ(context, input1->type, input2->type);
   output->type = input2->type;
@@ -358,9 +364,15 @@
   auto* params = reinterpret_cast<TfLiteAddParams*>(node->builtin_data);
   OpData* data = reinterpret_cast<OpData*>(node->user_data);
 
-  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
-  const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
-  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  const TfLiteTensor* input1;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor1, &input1));
+  const TfLiteTensor* input2;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputTensor2, &input2));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context,
+                    GetOutputSafe(context, node, kOutputTensor, &output));
 
   if (output->type == kTfLiteFloat32 || output->type == kTfLiteInt32) {
     EvalAdd<kernel_type>(context, node, params, data, input1, input2, output);
```
