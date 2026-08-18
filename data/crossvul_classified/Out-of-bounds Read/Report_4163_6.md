# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 45-85 of the vulnerable file.

  option->beam_width = m["beam_width"].AsInt32();
  option->top_paths = m["top_paths"].AsInt32();
  option->merge_repeated = m["merge_repeated"].AsBool();

  return option;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<CTCBeamSearchDecoderParams*>(buffer);
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  const CTCBeamSearchDecoderParams* option =
      reinterpret_cast<CTCBeamSearchDecoderParams*>(node->user_data);
  const int top_paths = option->top_paths;
  TF_LITE_ENSURE(context, option->beam_width >= top_paths);
  TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
  // The outputs should be top_paths * 3 + 1.
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 3 * top_paths + 1);

  const TfLiteTensor* inputs = GetInput(context, node, kInputsTensor);
  TF_LITE_ENSURE_EQ(context, NumDimensions(inputs), 3);
  // TensorFlow only supports float.
  TF_LITE_ENSURE_EQ(context, inputs->type, kTfLiteFloat32);
  const int batch_size = SizeOfDimension(inputs, 1);

  const TfLiteTensor* sequence_length =
      GetInput(context, node, kSequenceLengthTensor);
  TF_LITE_ENSURE_EQ(context, NumDimensions(sequence_length), 1);
  TF_LITE_ENSURE_EQ(context, NumElements(sequence_length), batch_size);
  // TensorFlow only supports int32.
  TF_LITE_ENSURE_EQ(context, sequence_length->type, kTfLiteInt32);

  // Resize decoded outputs.
  // Do not resize indices & values cause we don't know the values yet.
  for (int i = 0; i < top_paths; ++i) {
    TfLiteTensor* indices = GetOutput(context, node, i);
    SetTensorToDynamic(indices);
    TfLiteTensor* values = GetOutput(context, node, i + top_paths);
    SetTensorToDynamic(values);
    TfLiteTensor* output_shape = GetOutput(context, node, i + 2 * top_paths);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,14 +62,17 @@
   // The outputs should be top_paths * 3 + 1.
   TF_LITE_ENSURE_EQ(context, NumOutputs(node), 3 * top_paths + 1);
 
-  const TfLiteTensor* inputs = GetInput(context, node, kInputsTensor);
+  const TfLiteTensor* inputs;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputsTensor, &inputs));
   TF_LITE_ENSURE_EQ(context, NumDimensions(inputs), 3);
   // TensorFlow only supports float.
   TF_LITE_ENSURE_EQ(context, inputs->type, kTfLiteFloat32);
   const int batch_size = SizeOfDimension(inputs, 1);
 
-  const TfLiteTensor* sequence_length =
-      GetInput(context, node, kSequenceLengthTensor);
+  const TfLiteTensor* sequence_length;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kSequenceLengthTensor,
+                                          &sequence_length));
   TF_LITE_ENSURE_EQ(context, NumDimensions(sequence_length), 1);
   TF_LITE_ENSURE_EQ(context, NumElements(sequence_length), batch_size);
   // TensorFlow only supports int32.
@@ -78,17 +81,23 @@
   // Resize decoded outputs.
   // Do not resize indices & values cause we don't know the values yet.
   for (int i = 0; i < top_paths; ++i) {
-    TfLiteTensor* indices = GetOutput(context, node, i);
+    TfLiteTensor* indices;
+    TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, i, &indices));
     SetTensorToDynamic(indices);
-    TfLiteTensor* values = GetOutput(context, node, i + top_paths);
+    TfLiteTensor* values;
+    TF_LITE_ENSURE_OK(context,
+                      GetOutputSafe(context, node, i + top_paths, &values));
     SetTensorToDynamic(values);
-    TfLiteTensor* output_shape = GetOutput(context, node, i + 2 * top_paths);
+    TfLiteTensor* output_shape;
+    TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, i + 2 * top_paths,
+                                             &output_shape));
     SetTensorToDynamic(output_shape);
   }
 
   // Resize log probability outputs.
-  TfLiteTensor* log_probability_output =
-      GetOutput(context, node, top_paths * 3);
+  TfLiteTensor* log_probability_output;
+  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, top_paths * 3,
+                                           &log_probability_output));
   TfLiteIntArray* log_probability_output_shape_array = TfLiteIntArrayCreate(2);
   log_probability_output_shape_array->data[0] = batch_size;
   log_probability_output_shape_array->data[1] = top_paths;
@@ -127,13 +136,18 @@
     const int32_t p_num = num_entries[p];
 
     // Resize the decoded outputs.
-    TfLiteTensor* indices = GetOutput(context, node, p);
+    TfLiteTensor* indices;
+    TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, p, &indices));
     TF_LITE_ENSURE_OK(context, Resize(context, {p_num, 2}, indices));
 
-    TfLiteTensor* values = GetOutput(context, node, p + top_paths);
+    TfLiteTensor* values;
+    TF_LITE_ENSURE_OK(context,
+                      GetOutputSafe(context, node, p + top_paths, &values));
     TF_LITE_ENSURE_OK(context, Resize(context, {p_num}, values));
 
-    TfLiteTensor* decoded_shape = GetOutput(context, node, p + 2 * top_paths);
+    TfLiteTensor* decoded_shape;
+    TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, p + 2 * top_paths,
+                                             &decoded_shape));
     TF_LITE_ENSURE_OK(context, Resize(context, {2}, decoded_shape));
 
     int32_t max_decoded = 0;
@@ -161,9 +175,12 @@
 }
 
 TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
-  const TfLiteTensor* inputs = GetInput(context, node, kInputsTensor);
-  const TfLiteTensor* sequence_length =
-      GetInput(context, node, kSequenceLengthTensor);
+  const TfLiteTensor* inputs;
+  TF_LITE_ENSURE_OK(context,
+                    GetInputSafe(context, node, kInputsTensor, &inputs));
+  const TfLiteTensor* sequence_length;
+  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kSequenceLengthTensor,
+                                          &sequence_length));
   const CTCBeamSearchDecoderParams* option =
       reinterpret_cast<CTCBeamSearchDecoderParams*>(node->user_data);
 
@@ -207,7 +224,9 @@
   std::vector<std::vector<std::vector<int>>> best_paths(batch_size);
   std::vector<float> log_probs;
 
-  TfLiteTensor* log_probabilities = GetOutput(context, node, 3 * top_paths);
+  TfLiteTensor* log_probabilities;
+  TF_LITE_ENSURE_OK(
+      context, GetOutputSafe(context, node, 3 * top_paths, &log_probabilities));
   float* log_probabilities_output = GetTensorData<float>(log_probabilities);
 
   // Assumption: the blank index is num_classes - 1
```
