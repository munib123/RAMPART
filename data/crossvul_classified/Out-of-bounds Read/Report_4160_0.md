# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4160_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4160_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 235-276 of the vulnerable file.


void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

void LogSoftmaxFree(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<LogSoftmaxOpData*>(buffer);
}

void PreluFree(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<PreluOpData*>(buffer);
}

void* HardSwishInit(TfLiteContext* context, const char* buffer, size_t length) {
  return new HardSwishData;
}

TfLiteStatus GenericPrepare(TfLiteContext* context, TfLiteNode* node) {
  TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
  const TfLiteTensor* input = GetInput(context, node, 0);
  TfLiteTensor* output = GetOutput(context, node, 0);
  TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);

  return context->ResizeTensor(context, output,
                               TfLiteIntArrayCopy(input->dims));
}

void* ReluInit(TfLiteContext* context, const char* buffer, size_t length) {
  return new ReluOpData;
}

void ReluFree(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<ReluOpData*>(buffer);
}

TfLiteStatus ReluPrepare(TfLiteContext* context, TfLiteNode* node) {
  ReluOpData* data = reinterpret_cast<ReluOpData*>(node->user_data);
  TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
  const TfLiteTensor* input = GetInput(context, node, 0);
  TfLiteTensor* output = GetOutput(context, node, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,8 +252,10 @@
 TfLiteStatus GenericPrepare(TfLiteContext* context, TfLiteNode* node) {
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   return context->ResizeTensor(context, output,
@@ -272,8 +274,10 @@
   ReluOpData* data = reinterpret_cast<ReluOpData*>(node->user_data);
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   if (input->type == kTfLiteInt8 || input->type == kTfLiteUInt8) {
@@ -300,12 +304,14 @@
 
 TfLiteStatus HardSwishPrepare(TfLiteContext* context, TfLiteNode* node) {
   TF_LITE_ENSURE_STATUS(GenericPrepare(context, node));
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
 
   if (output->type == kTfLiteUInt8 || output->type == kTfLiteInt8) {
     HardSwishData* data = static_cast<HardSwishData*>(node->user_data);
     HardSwishParams* params = &data->params;
-    const TfLiteTensor* input = GetInput(context, node, 0);
+    const TfLiteTensor* input;
+    TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
     params->input_zero_point = input->params.zero_point;
     params->output_zero_point = output->params.zero_point;
     const float input_scale = input->params.scale;
@@ -337,8 +343,10 @@
 TfLiteStatus LeakyReluPrepare(TfLiteContext* context, TfLiteNode* node) {
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   LeakyReluOpData* data = reinterpret_cast<LeakyReluOpData*>(node->user_data);
@@ -366,8 +374,10 @@
 
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   if (kernel_type == kFixedPointOptimized) {
@@ -451,8 +461,10 @@
 
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   if (kernel_type == kFixedPointOptimized) {
@@ -546,8 +558,10 @@
 
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   if (output->type == kTfLiteInt16) {
     TF_LITE_ENSURE(context, input->type == kTfLiteInt8 ||
                                 input->type == kTfLiteUInt8 ||
@@ -614,8 +628,10 @@
 
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);
 
   if (input->type == kTfLiteUInt8 || input->type == kTfLiteInt8) {
@@ -650,9 +666,12 @@
 TfLiteStatus PreluPrepare(TfLiteContext* context, TfLiteNode* node) {
   TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
-  const TfLiteTensor* alpha = GetInput(context, node, 1);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
+  const TfLiteTensor* alpha;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &alpha));
   PreluOpData* data = reinterpret_cast<PreluOpData*>(node->user_data);
 
   TF_LITE_ENSURE_TYPES_EQ(context, input->type, alpha->type);
@@ -704,8 +723,10 @@
 }
 
 TfLiteStatus ReluEval(TfLiteContext* context, TfLiteNode* node) {
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   const ReluOpData* data = reinterpret_cast<ReluOpData*>(node->user_data);
   switch (input->type) {
     case kTfLiteFloat32: {
@@ -732,8 +753,10 @@
 }
 
 TfLiteStatus Relu1Eval(TfLiteContext* context, TfLiteNode* node) {
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   const ReluOpData* data = reinterpret_cast<ReluOpData*>(node->user_data);
   switch (input->type) {
     case kTfLiteFloat32: {
@@ -763,8 +786,10 @@
 TfLiteStatus HardSwishEval(TfLiteContext* context, TfLiteNode* node) {
   HardSwishData* data = static_cast<HardSwishData*>(node->user_data);
 
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   switch (input->type) {
     case kTfLiteFloat32: {
       if (kernel_type == kReference) {
@@ -814,8 +839,10 @@
 }
 
 TfLiteStatus Relu6Eval(TfLiteContext* context, TfLiteNode* node) {
-  const TfLiteTensor* input = GetInput(context, node, 0);
-  TfLiteTensor* output = GetOutput(context, node, 0);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
+  TfLiteTensor* output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
   ReluOpData* data = reinterpret_cast<ReluOpData*>(node->user_data);
... (diff truncated)
```
