# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4158_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4158_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 564-604 of the vulnerable file.

                "kTfLiteOptionalTensor should be defined -1");

  for (int i = 0; i < length; i++) {
    int index = indices[i];
    // Continue if index == kTfLiteOptionalTensor before additional comparisons
    // below, size_t(-1) is always >= context_tensors_size.
    if (index == kTfLiteOptionalTensor) {
      continue;
    }
    if (index < 0 || static_cast<size_t>(index) >= context_.tensors_size) {
      ReportError(
          "Invalid tensor index %d in %s. The subgraph has %d tensors\n", index,
          label, context_.tensors_size);
      consistent_ = false;
      return kTfLiteError;
    }
  }
  return kTfLiteOk;
}

namespace {
// Multiply two sizes and return true if overflow occurred;
// This is based off tensorflow/overflow.h but is simpler as we already
// have unsigned numbers. It is also generalized to work where sizeof(size_t)
// is not 8.
TfLiteStatus MultiplyAndCheckOverflow(size_t a, size_t b, size_t* product) {
  // Multiplying a * b where a and b are size_t cannot result in overflow in a
  // size_t accumulator if both numbers have no non-zero bits in their upper
  // half.
  constexpr size_t size_t_bits = 8 * sizeof(size_t);
  constexpr size_t overflow_upper_half_bit_position = size_t_bits / 2;
  *product = a * b;
  // If neither integers have non-zero bits past 32 bits can't overflow.
  // Otherwise check using slow devision.
  if (TFLITE_EXPECT_FALSE((a | b) >> overflow_upper_half_bit_position != 0)) {
    if (a != 0 && *product / a != b) return kTfLiteError;
  }
  return kTfLiteOk;
}
}  // namespace

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -581,6 +581,33 @@
   return kTfLiteOk;
 }
 
+// We have two arrays and we need to check that elements from one array don't
+// show up in the other. We could sort both arrays and then iterate with two
+// pointers from start to finish always increasing the smaller one but since
+// these arrays are usually short (<25 elements for inputs, usually <3 for
+// outputs), this might be slower than the naive approach (if arrays have size n
+// and m, with n >> m ~ O(1), first approach is O(nlogn) whereas the other is
+// O(n)). Plus, sorting the input and output arrays might not be something we
+// want as it destroys ordering of elements.
+//
+// If it turns out that this is an issue, we can switch to the other algorithm.
+TfLiteStatus Subgraph::CheckInputAndOutputForOverlap(const int* input_indices,
+                                                     int num_inputs,
+                                                     const int* output_indices,
+                                                     int num_outputs) {
+  for (int i = 0; i < num_inputs; i++) {
+    for (int j = 0; j < num_outputs; j++) {
+      if (input_indices[i] == output_indices[j]) {
+        ReportError("Tensor %d is both input %d and output %d\n",
+                    input_indices[i], i, j);
+        consistent_ = false;
+        return kTfLiteError;
+      }
+    }
+  }
+  return kTfLiteOk;
+}
+
 namespace {
 // Multiply two sizes and return true if overflow occurred;
 // This is based off tensorflow/overflow.h but is simpler as we already
@@ -706,6 +733,16 @@
   TF_LITE_ENSURE_OK(
       &context_,
       CheckTensorIndices("node outputs", outputs.data(), outputs.size()));
+
+  // For builtin ops, inputs and outputs must not overlap. Custom ops must do
+  // this check by themselves if they don't support overlapping tensors. This
+  // distinction is to allow custom ops to just forward a tensor, reusing it as
+  // both input and output.
+  if (builtin_data != nullptr) {
+    TF_LITE_ENSURE_OK(&context_, CheckInputAndOutputForOverlap(
+                                     inputs.data(), inputs.size(),
+                                     outputs.data(), outputs.size()));
+  }
 
   int new_node_index = nodes_and_registration_.size();
   if (node_index) *node_index = new_node_index;
```
