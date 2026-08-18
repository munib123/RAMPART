# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 311-351 of the vulnerable file.

  } else if (registration->builtin_code == kTfLiteBuiltinDepthwiseConv2d) {
    const auto* depthwise_conv_params =
        reinterpret_cast<const TfLiteDepthwiseConvParams*>(node->builtin_data);
    activation = depthwise_conv_params->activation;
  } else if (registration->builtin_code == kTfLiteBuiltinTransposeConv) {
    activation = kTfLiteActNone;
  } else {
    TF_LITE_KERNEL_LOG(
        context,
        "Invalid op: op must be Conv2D, DepthwiseConv2D or TransposeConv.");
    return false;
  }

  if (activation == kTfLiteActSignBit) {
    return false;
  }

  const int kOutputShapeTensor = 0;  // Only used for TransposeConv
  const int kWeightTensor = 1;
  const int kBiasTensor = 2;  // Only used for non-TransposeConv
  const TfLiteTensor* weights = GetInput(context, node, kWeightTensor);
  const int max_kernel_size = 16384;
  if (!IsConstantTensor(weights)) {
    return false;
  }
  if (weights->dims->data[1] > max_kernel_size ||
      weights->dims->data[2] > max_kernel_size) {
    return false;
  }
  if (registration->builtin_code == kTfLiteBuiltinTransposeConv) {
    if (!IsConstantTensor(GetInput(context, node, kOutputShapeTensor))) {
      return false;
    }
  } else {
    if (node->inputs->size >= kBiasTensor &&
        !IsConstantTensor(GetInput(context, node, kBiasTensor))) {
      return false;
    }
  }

  return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,7 +328,9 @@
   const int kOutputShapeTensor = 0;  // Only used for TransposeConv
   const int kWeightTensor = 1;
   const int kBiasTensor = 2;  // Only used for non-TransposeConv
-  const TfLiteTensor* weights = GetInput(context, node, kWeightTensor);
+  const TfLiteTensor* weights;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kWeightTensor, &weights));
   const int max_kernel_size = 16384;
   if (!IsConstantTensor(weights)) {
     return false;
```
