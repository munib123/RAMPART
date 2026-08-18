# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 122-162 of the vulnerable file.

                           const Q* input_data,
                           const RuntimeShape& output_shape, Q* output_data) {
  const int flat_size = MatchingFlatSize(input_shape, output_shape);
  for (int i = 0; i < flat_size; ++i) {
    const Q val = input_data[i];
    const Q clamped = val > upper ? upper : val < lower ? lower : val;
    output_data[i] = clamped;
  }
}

void* ReluInit(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(ReluOpData));
}

TfLiteStatus ReluPrepare(TfLiteContext* context, TfLiteNode* node) {
  TFLITE_DCHECK(node->user_data != nullptr);
  ReluOpData* data = static_cast<ReluOpData*>(node->user_data);

  const TfLiteTensor* input = GetInput(context, node, kInputTensor);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);

  if (input->type == kTfLiteInt8) {
    CalculateReluOpData<int8_t>(input, output, data);
  } else if (input->type == kTfLiteUInt8) {
    CalculateReluOpData<uint8_t>(input, output, data);
  }

  return kTfLiteOk;
}

TfLiteStatus ReluEval(TfLiteContext* context, TfLiteNode* node) {
  TFLITE_DCHECK(node->user_data != nullptr);
  const ReluOpData& data = *(static_cast<const ReluOpData*>(node->user_data));

  const TfLiteEvalTensor* input =
      tflite::micro::GetEvalInput(context, node, kInputTensor);
  TfLiteEvalTensor* output =
      tflite::micro::GetEvalOutput(context, node, kOutputTensor);

  switch (input->type) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,7 +139,9 @@
   ReluOpData* data = static_cast<ReluOpData*>(node->user_data);
 
   const TfLiteTensor* input = GetInput(context, node, kInputTensor);
+  TF_LITE_ENSURE(context, input != nullptr);
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output != nullptr);
 
   if (input->type == kTfLiteInt8) {
     CalculateReluOpData<int8_t>(input, output, data);
@@ -200,6 +202,7 @@
   Relu6OpData* data = static_cast<Relu6OpData*>(node->user_data);
 
   const TfLiteTensor* input = GetInput(context, node, kInputTensor);
+  TF_LITE_ENSURE(context, input != nullptr);
 
   if (input->type == kTfLiteInt8) {
     data->six_int8 = FloatToAsymmetricQuantizedInt8(6.0f, input->params.scale,
```
