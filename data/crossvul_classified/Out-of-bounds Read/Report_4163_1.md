# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4163_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4163_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1149-1189 of the vulnerable file.

          "Only sigmoid or tanh activation is supported.");
    }

    return absl::OkStatus();
  }

  absl::flat_hash_map<int, ValueId> new_variable_input_value_map_;
};

class MulOperationParser : public TFLiteOperationParser {
 public:
  absl::Status IsSupported(const TfLiteContext* context,
                           const TfLiteNode* tflite_node,
                           const TfLiteRegistration* registration) final {
    RETURN_IF_ERROR(CheckMaxSupportedOpVersion(registration, 3));
    if (tflite_node->inputs->size != 2) {
      return absl::UnimplementedError("MUL requires two input tensors.");
    }
    auto input0 = tflite::GetInput(context, tflite_node, 0);
    auto input1 = tflite::GetInput(context, tflite_node, 1);
    if (input0->dims->size == input1->dims->size) {
      // this code checks that at least one input of Mul not smaller in all
      // dimensions. Sometimes Mul used for matrix-vector multiplication that we
      // currently don't support. For example input0 HWC(1, 256, 1), input1
      // HWC(1, 1, 256) -> output HWC (1, 256, 256). In this case it can be
      // replaced with Convolution operation.
      bool first_has_smaller_dim = false;
      bool second_has_smaller_dim = false;
      for (int i = 0; i < input0->dims->size; ++i) {
        if (input0->dims->data[i] < input1->dims->data[i]) {
          first_has_smaller_dim = true;
        }
        if (input1->dims->data[i] < input0->dims->data[i]) {
          second_has_smaller_dim = true;
        }
      }
      if (first_has_smaller_dim && second_has_smaller_dim) {
        return absl::UnimplementedError(
            "MUL requires one tensor that not less than second in all "
            "dimensions.");
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1166,6 +1166,9 @@
     }
     auto input0 = tflite::GetInput(context, tflite_node, 0);
     auto input1 = tflite::GetInput(context, tflite_node, 1);
+    if (input0 == nullptr || input1 == nullptr) {
+      return absl::InvalidArgumentError("At least one input tensor is null");
+    }
     if (input0->dims->size == input1->dims->size) {
       // this code checks that at least one input of Mul not smaller in all
       // dimensions. Sometimes Mul used for matrix-vector multiplication that we
@@ -1380,7 +1383,10 @@
     RETURN_IF_ERROR(CheckInputsOutputs(context, tflite_node,
                                        /*runtime_inputs=*/1, /*outputs=*/1));
     RETURN_IF_ERROR(CheckTensorIsAvailable(context, tflite_node, 1));
-    auto pad_tensor = tflite::GetInput(context, tflite_node, 1);
+    const TfLiteTensor* pad_tensor = tflite::GetInput(context, tflite_node, 1);
+    if (pad_tensor == nullptr) {
+      return absl::InvalidArgumentError("Padding tensor was null");
+    }
     if (pad_tensor->dims->size != 2) {
       return absl::InvalidArgumentError(absl::StrCat(
           "Invalid paddings tensor dimension: expected 2 dim, got ",
```
