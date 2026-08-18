# CrossVul Fix Pair: Heap-based Buffer Overflow in cpp
**Pair ID:** 4148_0
**Vulnerability Class:** Heap-based Buffer Overflow
**CWE:** CWE-122
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4148_0`)

## Vulnerability Information & PoC

## Description
Heap-based Buffer Overflow - A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine ...

## Vulnerable Code
```cpp
Lines 161-201 of the vulnerable file.

  int minlength_;
  bool binary_output_;
};

template <class T, class W>
class SparseCount : public OpKernel {
 public:
  explicit SparseCount(OpKernelConstruction* context) : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("minlength", &minlength_));
    OP_REQUIRES_OK(context, context->GetAttr("maxlength", &maxlength_));
    OP_REQUIRES_OK(context, context->GetAttr("binary_output", &binary_output_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& indices = context->input(0);
    const Tensor& values = context->input(1);
    const Tensor& shape = context->input(2);
    const Tensor& weights = context->input(3);
    bool use_weights = weights.NumElements() > 0;

    bool is_1d = shape.NumElements() == 1;
    int num_batches = is_1d ? 1 : shape.flat<int64>()(0);
    int num_values = values.NumElements();

    const auto indices_values = indices.matrix<int64>();
    const auto values_values = values.flat<T>();
    const auto weight_values = weights.flat<W>();

    auto per_batch_counts = BatchedMap<W>(num_batches);

    T max_value = 0;

    for (int idx = 0; idx < num_values; ++idx) {
      int batch = is_1d ? 0 : indices_values(idx, 0);
      const auto& value = values_values(idx);
      if (value >= 0 && (maxlength_ <= 0 || value < maxlength_)) {
        if (binary_output_) {
          per_batch_counts[batch][value] = 1;
        } else if (use_weights) {
          per_batch_counts[batch][value] += weight_values(idx);
        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,9 +178,29 @@
     const Tensor& weights = context->input(3);
     bool use_weights = weights.NumElements() > 0;
 
+    OP_REQUIRES(context, TensorShapeUtils::IsMatrix(indices.shape()),
+                errors::InvalidArgument(
+                    "Input indices must be a 2-dimensional tensor. Got: ",
+                    indices.shape().DebugString()));
+
+    if (use_weights) {
+      OP_REQUIRES(
+          context, weights.shape() == values.shape(),
+          errors::InvalidArgument(
+              "Weights and values must have the same shape. Weight shape: ",
+              weights.shape().DebugString(),
+              "; values shape: ", values.shape().DebugString()));
+    }
+
     bool is_1d = shape.NumElements() == 1;
     int num_batches = is_1d ? 1 : shape.flat<int64>()(0);
     int num_values = values.NumElements();
+
+    OP_REQUIRES(context, num_values == indices.shape().dim_size(0),
+                errors::InvalidArgument(
+                    "Number of values must match first dimension of indices.",
+                    "Got ", num_values,
+                    " values, indices shape: ", indices.shape().DebugString()));
 
     const auto indices_values = indices.matrix<int64>();
     const auto values_values = values.flat<T>();
@@ -235,11 +255,32 @@
     bool use_weights = weights.NumElements() > 0;
     bool is_1d = false;
 
+    if (use_weights) {
+      OP_REQUIRES(
+          context, weights.shape() == values.shape(),
+          errors::InvalidArgument(
+              "Weights and values must have the same shape. Weight shape: ",
+              weights.shape().DebugString(),
+              "; values shape: ", values.shape().DebugString()));
+    }
+
     const auto splits_values = splits.flat<int64>();
     const auto values_values = values.flat<T>();
     const auto weight_values = weights.flat<W>();
     int num_batches = splits.NumElements() - 1;
     int num_values = values.NumElements();
+
+    OP_REQUIRES(
+        context, num_batches > 0,
+        errors::InvalidArgument(
+            "Must provide at least 2 elements for the splits argument"));
+    OP_REQUIRES(context, splits_values(0) == 0,
+                errors::InvalidArgument("Splits must start with 0, not with ",
+                                        splits_values(0)));
+    OP_REQUIRES(context, splits_values(num_batches) == num_values,
+                errors::InvalidArgument(
+                    "Splits must end with the number of values, got ",
+                    splits_values(num_batches), " instead of ", num_values));
 
     auto per_batch_counts = BatchedMap<W>(num_batches);
     T max_value = 0;
```
