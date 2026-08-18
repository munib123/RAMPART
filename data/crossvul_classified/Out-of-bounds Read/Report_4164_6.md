# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 80-120 of the vulnerable file.

                             const TfLiteConvParams* params, int width,
                             int height, int filter_width, int filter_height,
                             int out_width, int out_height,
                             const TfLiteType data_type, OpData* data) {
  bool has_bias = node->inputs->size == 3;
  // Check number of inputs/outputs
  TF_LITE_ENSURE(context, has_bias || node->inputs->size == 2);
  TF_LITE_ENSURE_EQ(context, node->outputs->size, 1);

  // Matching GetWindowedOutputSize in TensorFlow.
  auto padding = params->padding;
  data->padding = ComputePaddingHeightWidth(
      params->stride_height, params->stride_width,
      params->dilation_height_factor, params->dilation_width_factor, height,
      width, filter_height, filter_width, padding, &out_height, &out_width);

  // Note that quantized inference requires that all tensors have their
  // parameters set. This is usually done during quantized training.
  if (data_type != kTfLiteFloat32) {
    const TfLiteTensor* input = GetInput(context, node, kInputTensor);
    const TfLiteTensor* filter = GetInput(context, node, kFilterTensor);
    const TfLiteTensor* bias =
        GetOptionalInputTensor(context, node, kBiasTensor);
    TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
    int output_channels = filter->dims->data[kConvQuantizedDimension];

    TF_LITE_ENSURE_STATUS(tflite::PopulateConvolutionQuantizationParams(
        context, input, filter, bias, output, params->activation,
        &data->output_multiplier, &data->output_shift,
        &data->output_activation_min, &data->output_activation_max,
        data->per_channel_output_multiplier,
        reinterpret_cast<int*>(data->per_channel_output_shift),
        output_channels));
  }
  return kTfLiteOk;
}

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(OpData));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,10 +97,13 @@
   // parameters set. This is usually done during quantized training.
   if (data_type != kTfLiteFloat32) {
     const TfLiteTensor* input = GetInput(context, node, kInputTensor);
+    TF_LITE_ENSURE(context, input != nullptr);
     const TfLiteTensor* filter = GetInput(context, node, kFilterTensor);
+    TF_LITE_ENSURE(context, filter != nullptr);
     const TfLiteTensor* bias =
         GetOptionalInputTensor(context, node, kBiasTensor);
     TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+    TF_LITE_ENSURE(context, output != nullptr);
     int output_channels = filter->dims->data[kConvQuantizedDimension];
 
     TF_LITE_ENSURE_STATUS(tflite::PopulateConvolutionQuantizationParams(
@@ -127,8 +130,11 @@
   const auto params = static_cast<const TfLiteConvParams*>(node->builtin_data);
 
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output != nullptr);
   const TfLiteTensor* input = GetInput(context, node, kInputTensor);
+  TF_LITE_ENSURE(context, input != nullptr);
   const TfLiteTensor* filter = GetInput(context, node, kFilterTensor);
+  TF_LITE_ENSURE(context, filter != nullptr);
 
   int input_width = input->dims->data[2];
   int input_height = input->dims->data[1];
```
