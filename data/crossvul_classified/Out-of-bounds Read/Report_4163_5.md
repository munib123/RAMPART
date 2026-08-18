# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 109-146 of the vulnerable file.


TfLiteStatus ReshapeOpBuilder::RegisterOutputs(const TfLiteIntArray* outputs,
                                               TfLiteContext* context) {
  graph_builder_->AddTensorWithID(outputs->data[0], GetOutput(context));
  return kTfLiteOk;
}

bool IsReshapeOpSupported(const TfLiteRegistration* registration,
                          const TfLiteNode* node, TfLiteContext* context,
                          int coreml_version) {
  if (coreml_version >= 3) {
    return false;
  }
  if (node->inputs->size == 1) {
    const auto* params =
        reinterpret_cast<TfLiteReshapeParams*>(node->builtin_data);
    return params->num_dimensions == 3 || params->num_dimensions == 4;
  }

  const int kShapeTensor = 1;
  const auto* shape = GetInput(context, node, kShapeTensor);
  if (shape->allocation_type != kTfLiteMmapRo) {
    TF_LITE_KERNEL_LOG(context, "Reshape has non-const shape.");
    return false;
  }
  const bool is_shape_tensor =
      shape->dims->size == 1 && shape->type == kTfLiteInt32;
  return is_shape_tensor &&
         (shape->dims->data[0] == 3 || shape->dims->data[0] == 4);
}

OpBuilder* CreateReshapeOpBuilder(GraphBuilder* graph_builder) {
  return new ReshapeOpBuilder(graph_builder);
}

}  // namespace coreml
}  // namespace delegates
}  // namespace tflite
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -126,7 +126,8 @@
   }
 
   const int kShapeTensor = 1;
-  const auto* shape = GetInput(context, node, kShapeTensor);
+  const TfLiteTensor* shape;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kShapeTensor, &shape));
   if (shape->allocation_type != kTfLiteMmapRo) {
     TF_LITE_KERNEL_LOG(context, "Reshape has non-const shape.");
     return false;
```
