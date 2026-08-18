# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4165_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4165_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 17-57 of the vulnerable file.


#include "tensorflow/lite/c/common.h"
#include "tensorflow/lite/kernels/internal/reference/reference_ops.h"
#include "tensorflow/lite/kernels/internal/tensor.h"
#include "tensorflow/lite/kernels/internal/tensor_ctypes.h"
#include "tensorflow/lite/kernels/kernel_util.h"

namespace tflite {
namespace ops {
namespace builtin {
namespace segment_sum {

static const int kInputDataTensor = 0;
static const int kInputSegmentIdsTensor = 1;
static const int kOutputTensor = 0;

TfLiteStatus ResizeOutputTensor(TfLiteContext* context,
                                const TfLiteTensor* data,
                                const TfLiteTensor* segment_ids,
                                TfLiteTensor* output) {
  int max_index = -1;
  const int segment_id_size = segment_ids->dims->data[0];
  if (segment_id_size > 0) {
    max_index = segment_ids->data.i32[segment_id_size - 1];
  }
  const int data_rank = NumDimensions(data);
  TfLiteIntArray* output_shape = TfLiteIntArrayCreate(NumDimensions(data));
  output_shape->data[0] = max_index + 1;
  for (int i = 1; i < data_rank; ++i) {
    output_shape->data[i] = data->dims->data[i];
  }
  return context->ResizeTensor(context, output, output_shape);
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  TF_LITE_ENSURE_EQ(context, NumInputs(node), 2);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
  const TfLiteTensor* data = GetInput(context, node, kInputDataTensor);
  const TfLiteTensor* segment_ids =
      GetInput(context, node, kInputSegmentIdsTensor);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,11 +34,24 @@
                                 const TfLiteTensor* data,
                                 const TfLiteTensor* segment_ids,
                                 TfLiteTensor* output) {
-  int max_index = -1;
+  // Segment ids should be of same cardinality as first input dimension and they
+  // should be increasing by at most 1, from 0 (e.g., [0, 0, 1, 2, 3] is valid)
   const int segment_id_size = segment_ids->dims->data[0];
-  if (segment_id_size > 0) {
-    max_index = segment_ids->data.i32[segment_id_size - 1];
+  TF_LITE_ENSURE_EQ(context, segment_id_size, data->dims->data[0]);
+  int previous_segment_id = -1;
+  for (int i = 0; i < segment_id_size; i++) {
+    const int current_segment_id = GetTensorData<int32_t>(segment_ids)[i];
+    if (i == 0) {
+      TF_LITE_ENSURE_EQ(context, current_segment_id, 0);
+    } else {
+      int delta = current_segment_id - previous_segment_id;
+      TF_LITE_ENSURE(context, delta == 0 || delta == 1);
+    }
+    previous_segment_id = current_segment_id;
   }
+
+  const int max_index = previous_segment_id;
+
   const int data_rank = NumDimensions(data);
   TfLiteIntArray* output_shape = TfLiteIntArrayCreate(NumDimensions(data));
   output_shape->data[0] = max_index + 1;
```
