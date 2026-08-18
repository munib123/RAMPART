# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 136-177 of the vulnerable file.

  return new FullyConnectedOpBuilder(graph_builder);
}

bool IsFloatType(TfLiteType type) {
  return type == kTfLiteFloat32 || type == kTfLiteFloat16;
}

bool IsFullyConnectedOpSupported(const TfLiteRegistration* registration,
                                 const TfLiteNode* node,
                                 TfLiteContext* context) {
  if (node->builtin_data == nullptr) return false;
  const auto* fc_params =
      reinterpret_cast<const TfLiteFullyConnectedParams*>(node->builtin_data);
  const int kInput = 0;
  const int kWeights = 1;
  const int kBias = 2;

  if (fc_params->weights_format != kTfLiteFullyConnectedWeightsFormatDefault) {
    return false;
  }
  const TfLiteTensor* input = GetInput(context, node, kInput);
  const TfLiteTensor* weights = GetInput(context, node, kWeights);

  if (!IsFloatType(input->type)) {
    return false;
  }
  if (!IsFloatType(weights->type) || !IsConstantTensor(weights)) {
    return false;
  }
  // Core ML 2 only supports single-batch fully connected layer, thus dimensions
  // except the last one should be 1.
  if (input->dims->data[input->dims->size - 1] != NumElements(input)) {
    return false;
  }

  if (node->inputs->size > 2) {
    const TfLiteTensor* bias = GetInput(context, node, kBias);
    if (!IsFloatType(bias->type) || !IsConstantTensor(bias)) {
      return false;
    }
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,8 +153,10 @@
   if (fc_params->weights_format != kTfLiteFullyConnectedWeightsFormatDefault) {
     return false;
   }
-  const TfLiteTensor* input = GetInput(context, node, kInput);
-  const TfLiteTensor* weights = GetInput(context, node, kWeights);
+  const TfLiteTensor* input;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInput, &input));
+  const TfLiteTensor* weights;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kWeights, &weights));
 
   if (!IsFloatType(input->type)) {
     return false;
@@ -169,7 +171,8 @@
   }
 
   if (node->inputs->size > 2) {
-    const TfLiteTensor* bias = GetInput(context, node, kBias);
+    const TfLiteTensor* bias;
+    TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kBias, &bias));
     if (!IsFloatType(bias->type) || !IsConstantTensor(bias)) {
       return false;
     }
```
