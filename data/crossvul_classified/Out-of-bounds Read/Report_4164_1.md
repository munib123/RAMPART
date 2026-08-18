# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4164_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4164_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 184-224 of the vulnerable file.

                           tflite::micro::GetTensorData<uint8_t>(input2),
                           tflite::micro::GetTensorShape(output),
                           tflite::micro::GetTensorData<uint8_t>(output));
      }
    }
  }

  return kTfLiteOk;
}

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  TFLITE_DCHECK(context->AllocatePersistentBuffer != nullptr);
  return context->AllocatePersistentBuffer(context, sizeof(OpData));
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  TFLITE_DCHECK(node->user_data != nullptr);
  TFLITE_DCHECK(node->builtin_data != nullptr);

  const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
  const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
  TfLiteTensor* output = GetOutput(context, node, kOutputTensor);

  OpData* data = static_cast<OpData*>(node->user_data);
  auto* params = reinterpret_cast<TfLiteAddParams*>(node->builtin_data);

  TF_LITE_ENSURE_STATUS(
      CalculateOpData(context, params, input1, input2, output, data));

  return kTfLiteOk;
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteAddParams*>(node->builtin_data);

  TFLITE_DCHECK(node->user_data != nullptr);
  const OpData* data = static_cast<const OpData*>(node->user_data);

  const TfLiteEvalTensor* input1 =
      tflite::micro::GetEvalInput(context, node, kInputTensor1);
  const TfLiteEvalTensor* input2 =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,8 +201,11 @@
   TFLITE_DCHECK(node->builtin_data != nullptr);
 
   const TfLiteTensor* input1 = GetInput(context, node, kInputTensor1);
+  TF_LITE_ENSURE(context, input1 != nullptr);
   const TfLiteTensor* input2 = GetInput(context, node, kInputTensor2);
+  TF_LITE_ENSURE(context, input2 != nullptr);
   TfLiteTensor* output = GetOutput(context, node, kOutputTensor);
+  TF_LITE_ENSURE(context, output != nullptr);
 
   OpData* data = static_cast<OpData*>(node->user_data);
   auto* params = reinterpret_cast<TfLiteAddParams*>(node->builtin_data);
```
