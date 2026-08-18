# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 80-120 of the vulnerable file.

                                           TfLiteContext* context) {
  if (outputs->size != 1) {
    TF_LITE_KERNEL_LOG(context, "Wrong # of outputs to Padding!.");
    return kTfLiteError;
  }
  graph_builder_->AddTensorWithID(outputs->data[0], GetOutput(context));
  return kTfLiteOk;
}

OpBuilder* CreatePadOpBuilder(GraphBuilder* graph_builder) {
  return new PadOpBuilder(graph_builder, PadType::kPad);
}

OpBuilder* CreateMirrorPadOpBuilder(GraphBuilder* graph_builder) {
  return new PadOpBuilder(graph_builder, PadType::kMirrorPad);
}

bool IsPadOpSupported(const TfLiteRegistration* registration,
                      const TfLiteNode* node, TfLiteContext* context) {
  // padding is d x 2 tensor, where d is the dimension of input.
  const TfLiteTensor* padding = GetInput(context, node, 1);
  if (!IsConstantTensor(padding)) {
    TF_LITE_KERNEL_LOG(context,
                       "%s: Only constant padding is supported for PAD.",
                       padding->name);
    return false;
  }
  if (padding->dims->data[0] != 4 || padding->dims->data[1] != 2) {
    TF_LITE_KERNEL_LOG(context, "%s: Only 4D inputs are supported for PAD.",
                       padding->name);
    return false;
  }
  const int32_t* padding_data = GetTensorData<int32_t>(padding);
  if (!(padding_data[0] == 0 && padding_data[1] == 0)) {
    TF_LITE_KERNEL_LOG(
        context, "%s: Padding for batch dimension is not supported in PAD.",
        padding->name);
    return false;
  }

  if (!(padding_data[6] == 0 && padding_data[7] == 0)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,8 @@
 bool IsPadOpSupported(const TfLiteRegistration* registration,
                       const TfLiteNode* node, TfLiteContext* context) {
   // padding is d x 2 tensor, where d is the dimension of input.
-  const TfLiteTensor* padding = GetInput(context, node, 1);
+  const TfLiteTensor* padding;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &padding));
   if (!IsConstantTensor(padding)) {
     TF_LITE_KERNEL_LOG(context,
                        "%s: Only constant padding is supported for PAD.",
```
