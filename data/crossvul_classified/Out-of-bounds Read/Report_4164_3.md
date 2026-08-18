# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 60-100 of the vulnerable file.

// These fields control the stride period of a strided streaming model. This op
// returns kTfLiteAbort until cycles_until_run-- is zero.  At this time,
// cycles_until_run is reset to cycles_max.
struct OpData {
  int cycles_until_run;
  int cycles_max;
};

// These constants represent constants specific to the music detect model.
// They exist until (b/132070898) is fixed.
constexpr int kMaxOpDataSize = 7;
int op_data_counter = 0;
OpData op_data_array[kMaxOpDataSize];

}  // namespace

void Free(TfLiteContext* context, void* buffer) { op_data_counter = 0; }

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  const TfLiteTensor* input = GetInput(context, node, kInputTensor);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);

  TF_LITE_ENSURE(context, input != nullptr);
  TF_LITE_ENSURE(context, output != nullptr);
  TF_LITE_ENSURE_EQ(context, 1, output->dims->data[0]);
  TF_LITE_ENSURE_EQ(context, 1, input->dims->data[0]);
  TF_LITE_ENSURE_EQ(context, 1, input->dims->data[1]);
  TF_LITE_ENSURE_EQ(context, 1, output->dims->data[2]);
  TF_LITE_ENSURE_EQ(context, 1, input->dims->data[2]);
  TF_LITE_ENSURE_EQ(context, output->dims->data[3], input->dims->data[3]);

  TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);

  // The circular buffer custom operator currently only supports int8_t.
  TF_LITE_ENSURE_TYPES_EQ(context, input->type, kTfLiteInt8);

  // TODO(b/132070898): Use statically slotted OpData structures until a
  // scratch memory API is ready.
  TFLITE_DCHECK_LE(op_data_counter, kMaxOpDataSize);
  OpData* op_data = &op_data_array[op_data_counter++];
  // The last circular buffer layer (length 5) simply accumulates outputs, and
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,9 @@
 
 TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
   const TfLiteTensor* input = GetInput(context, node, kInputTensor);
+  TF_LITE_ENSURE(context, input != nullptr);
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output != nullptr);
 
   TF_LITE_ENSURE(context, input != nullptr);
   TF_LITE_ENSURE(context, output != nullptr);
```
