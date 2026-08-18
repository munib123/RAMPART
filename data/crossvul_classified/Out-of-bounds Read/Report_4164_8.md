# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_8
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_8`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 35-75 of the vulnerable file.

  // be represented as a fixed point multiplier plus a left shift.
  int32_t output_multiplier;
  int output_shift;
  int32_t output_zero_point;
};

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(OpData));
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  TFLITE_DCHECK(node->user_data != nullptr);
  OpData* data = static_cast<OpData*>(node->user_data);

  TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  // TODO(b/140515557): Add cached dequant to improve hybrid model performance.
  const TfLiteTensor* input = GetInput(context, node, 0);
  TfLiteTensor* output = GetOutput(context, node, 0);

  TF_LITE_ENSURE(context, input->type == kTfLiteUInt8 ||
                              input->type == kTfLiteInt8 ||
                              input->type == kTfLiteInt16);
  TF_LITE_ENSURE(
      context, output->type == kTfLiteFloat32 || output->type == kTfLiteInt32);

  if (output->type == kTfLiteInt32) {
    const double effective_output_scale =
        static_cast<double>(input->params.scale) /
        static_cast<double>(output->params.scale);
    QuantizeMultiplier(effective_output_scale, &data->output_multiplier,
                       &data->output_shift);
  }

  data->quantization_params.zero_point = input->params.zero_point;
  data->quantization_params.scale = static_cast<double>(input->params.scale);
  data->output_zero_point = output->params.zero_point;
  return kTfLiteOk;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,9 @@
 
   // TODO(b/140515557): Add cached dequant to improve hybrid model performance.
   const TfLiteTensor* input = GetInput(context, node, 0);
+  TF_LITE_ENSURE(context, input != nullptr);
   TfLiteTensor* output = GetOutput(context, node, 0);
+  TF_LITE_ENSURE(context, output != nullptr);
 
   TF_LITE_ENSURE(context, input->type == kTfLiteUInt8 ||
                               input->type == kTfLiteInt8 ||
```
