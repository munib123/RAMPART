# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 119-160 of the vulnerable file.

  TFLITE_DCHECK(node->user_data != nullptr);
  const OpData* data = static_cast<const OpData*>(node->user_data);

  reference_ops::ConcatenationWithScaling(
      data->params, inputs_shape_ptr, inputs_data,
      tflite::micro::GetTensorShape(output),
      tflite::micro::GetTensorData<uint8_t>(output));
}

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(OpData));
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  // This function only checks the types. Additional shape validations are
  // performed in the reference implementation called during Eval().
  const TfLiteConcatenationParams* params =
      reinterpret_cast<TfLiteConcatenationParams*>(node->builtin_data);

  TfLiteType input_type = GetInput(context, node, 0)->type;
  TfLiteType output_type = GetOutput(context, node, kOutputTensor)->type;

  // Check activation and input type
  TF_LITE_ENSURE_EQ(context, params->activation, kTfLiteActNone);
  TF_LITE_ENSURE(context,
                 input_type == kTfLiteFloat32 || input_type == kTfLiteUInt8 ||
                     input_type == kTfLiteInt8 || input_type == kTfLiteInt32 ||
                     input_type == kTfLiteInt64);

  // Output type must match input type
  TF_LITE_ENSURE_EQ(context, output_type, input_type);

  // This implementation does not support large number of input tensors
  const int num_inputs = NumInputs(node);
  TF_LITE_ENSURE(context, num_inputs <= kMaxInputNum);

  // Shapes with dimensions >4 are not yet supported with static allocation.
  for (int i = 0; i < num_inputs; ++i) {
    const TfLiteTensor* input = GetInput(context, node, i);
    int num_dimensions = NumDimensions(input);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,8 +136,12 @@
   const TfLiteConcatenationParams* params =
       reinterpret_cast<TfLiteConcatenationParams*>(node->builtin_data);
 
-  TfLiteType input_type = GetInput(context, node, 0)->type;
-  TfLiteType output_type = GetOutput(context, node, kOutputTensor)->type;
+  const TfLiteTensor* input_tensor = GetInput(context, node, 0);
+  TF_LITE_ENSURE(context, input_tensor != nullptr);
+  TfLiteType input_type = input_tensor->type;
+  const TfLiteTensor* output_tensor = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output_tensor != nullptr);
+  TfLiteType output_type = output_tensor->type;
 
   // Check activation and input type
   TF_LITE_ENSURE_EQ(context, params->activation, kTfLiteActNone);
@@ -156,6 +160,7 @@
   // Shapes with dimensions >4 are not yet supported with static allocation.
   for (int i = 0; i < num_inputs; ++i) {
     const TfLiteTensor* input = GetInput(context, node, i);
+    TF_LITE_ENSURE(context, input != nullptr);
     int num_dimensions = NumDimensions(input);
 
     if (num_dimensions > 4) {
@@ -173,6 +178,7 @@
   OpData* data = static_cast<OpData*>(node->user_data);
 
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output != nullptr);
 
   switch (output_type) {  // Already know in/outtypes are same.
     case kTfLiteFloat32:
@@ -199,6 +205,7 @@
       // Store input scale and zero point values in OpParams:
       for (int i = 0; i < node->inputs->size; ++i) {
         const TfLiteTensor* t = GetInput(context, node, i);
+        TF_LITE_ENSURE(context, t != nullptr);
         input_scales[i] = t->params.scale;
         input_zero_points[i] = t->params.zero_point;
       }
@@ -220,7 +227,9 @@
 }
 
 TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
-  TfLiteType output_type = GetOutput(context, node, kOutputTensor)->type;
+  const TfLiteTensor* output_tensor = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output_tensor != nullptr);
+  TfLiteType output_type = output_tensor->type;
 
   switch (output_type) {  // Already know in/outtypes are same.
     case kTfLiteFloat32:
```
