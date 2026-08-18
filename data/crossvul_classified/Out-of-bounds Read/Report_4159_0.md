# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4159_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4159_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 58-103 of the vulnerable file.

  return tensor->is_variable ? tensor : nullptr;
}

TfLiteTensor* GetOutput(TfLiteContext* context, const TfLiteNode* node,
                        int index) {
  if (index >= 0 && index < node->outputs->size) {
    const int tensor_index = node->outputs->data[index];
    if (tensor_index != kTfLiteOptionalTensor) {
      if (context->tensors != nullptr) {
        return &context->tensors[tensor_index];
      } else {
        return context->GetTensor(context, tensor_index);
      }
    }
  }
  return nullptr;
}

const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
                                           const TfLiteNode* node, int index) {
  const bool use_tensor = index < node->inputs->size &&
                          node->inputs->data[index] != kTfLiteOptionalTensor;
  if (use_tensor) {
    return GetMutableInput(context, node, index);
  }
  return nullptr;
}

// Per-axis
TfLiteStatus PopulateConvolutionQuantizationParams(
    TfLiteContext* context, const TfLiteTensor* input,
    const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output,
    const TfLiteFusedActivation& activation, int32_t* multiplier, int* shift,
    int32_t* output_activation_min, int32_t* output_activation_max,
    int32_t* per_channel_multiplier, int* per_channel_shift) {
  const auto* affine_quantization =
      reinterpret_cast<TfLiteAffineQuantization*>(filter->quantization.params);
  return PopulateConvolutionQuantizationParams(
      context, input, filter, bias, output, activation, multiplier, shift,
      output_activation_min, output_activation_max, per_channel_multiplier,
      per_channel_shift, affine_quantization->scale->size);
}

// Per-axis & per-tensor
TfLiteStatus PopulateConvolutionQuantizationParams(
    TfLiteContext* context, const TfLiteTensor* input,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,12 +75,7 @@
 
 const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
                                            const TfLiteNode* node, int index) {
-  const bool use_tensor = index < node->inputs->size &&
-                          node->inputs->data[index] != kTfLiteOptionalTensor;
-  if (use_tensor) {
-    return GetMutableInput(context, node, index);
-  }
-  return nullptr;
+  return GetInput(context, node, index);
 }
 
 // Per-axis
```
