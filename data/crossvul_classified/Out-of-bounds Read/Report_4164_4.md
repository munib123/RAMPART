# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 602-642 of the vulnerable file.

    default:
      TF_LITE_KERNEL_LOG(context, "Type %s (%d) not supported.",
                         TfLiteTypeGetName(input1->type), input1->type);
      return kTfLiteError;
  }
  return kTfLiteOk;
}

}  // namespace

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(OpData));
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  TFLITE_DCHECK(node->user_data != nullptr);
  OpData* data = static_cast<OpData*>(node->user_data);

  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
  const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);

  if (input1->type == kTfLiteUInt8 || input1->type == kTfLiteInt8) {
    auto input1_offset = -input1->params.zero_point;
    auto input2_offset = -input2->params.zero_point;
    const int kLeftShift = 8;

    int32_t input1_multiplier;
    int input1_shift;
    QuantizeMultiplierSmallerThanOneExp(
        static_cast<double>(input1->params.scale), &input1_multiplier,
        &input1_shift);
    int32_t input2_multiplier;
    int input2_shift;
    QuantizeMultiplierSmallerThanOneExp(
        static_cast<double>(input2->params.scale), &input2_multiplier,
        &input2_shift);

    data->params.left_shift = kLeftShift;
    data->params.input1_offset = input1_offset;
    data->params.input1_multiplier = input1_multiplier;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -619,7 +619,9 @@
   OpData* data = static_cast<OpData*>(node->user_data);
 
   const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
+  TF_LITE_ENSURE(context, input1 != nullptr);
   const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
+  TF_LITE_ENSURE(context, input2 != nullptr);
 
   if (input1->type == kTfLiteUInt8 || input1->type == kTfLiteInt8) {
     auto input1_offset = -input1->params.zero_point;
```
