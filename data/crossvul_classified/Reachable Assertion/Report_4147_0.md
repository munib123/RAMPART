# CrossVul Fix Pair: Reachable Assertion in cpp
**Pair ID:** 4147_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4147_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```cpp
Lines 219-259 of the vulnerable file.


template <typename T>
class SparseFillEmptyRowsGradOp : public OpKernel {
 public:
  explicit SparseFillEmptyRowsGradOp(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* context) override {
    const Tensor* reverse_index_map_t;
    const Tensor* grad_values_t;
    OP_REQUIRES_OK(context,
                   context->input("reverse_index_map", &reverse_index_map_t));
    OP_REQUIRES_OK(context, context->input("grad_values", &grad_values_t));

    const CPUDevice& d = context->eigen_device<CPUDevice>();

    OP_REQUIRES(
        context, TensorShapeUtils::IsVector(reverse_index_map_t->shape()),
        errors::InvalidArgument("reverse_index_map must be a vector, saw: ",
                                reverse_index_map_t->shape().DebugString()));

    const auto reverse_index_map = reverse_index_map_t->vec<int64>();
    const auto grad_values = grad_values_t->vec<T>();

    const int64 N = reverse_index_map_t->shape().dim_size(0);
    const int64 N_full = grad_values_t->shape().dim_size(0);

    Tensor* d_values_t;
    OP_REQUIRES_OK(context, context->allocate_output(
                                "d_values", TensorShape({N}), &d_values_t));
    auto d_values = d_values_t->vec<T>();
    Tensor* d_default_value_t;
    OP_REQUIRES_OK(context,
                   context->allocate_output("d_default_value", TensorShape({}),
                                            &d_default_value_t));
    T& d_default_value = d_default_value_t->scalar<T>()();
    d_default_value = T();

    Tensor visited_t;
    OP_REQUIRES_OK(context, context->allocate_temp(
                                DT_BOOL, TensorShape({N_full}), &visited_t));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -236,6 +236,9 @@
         context, TensorShapeUtils::IsVector(reverse_index_map_t->shape()),
         errors::InvalidArgument("reverse_index_map must be a vector, saw: ",
                                 reverse_index_map_t->shape().DebugString()));
+    OP_REQUIRES(context, TensorShapeUtils::IsVector(grad_values_t->shape()),
+                errors::InvalidArgument("grad_values must be a vector, saw: ",
+                                        grad_values_t->shape().DebugString()));
 
     const auto reverse_index_map = reverse_index_map_t->vec<int64>();
     const auto grad_values = grad_values_t->vec<T>();
@@ -264,8 +267,13 @@
       // Locate the index of the output of the forward prop associated
       // with this location in the input of the forward prop.  Copy
       // the gradient into it.  Mark it as visited.
-      d_values(i) = grad_values(reverse_index_map(i));
-      visited(reverse_index_map(i)) = true;
+      int64 reverse_index = reverse_index_map(i);
+      OP_REQUIRES(
+          context, 0 <= reverse_index && reverse_index < N_full,
+          errors::InvalidArgument("Elements in reverse index must be in [0, ",
+                                  N_full, ") but got ", reverse_index));
+      d_values(i) = grad_values(reverse_index);
+      visited(reverse_index) = true;
     }
     for (int j = 0; j < N_full; ++j) {
       // The default value gradient gets the accumulated remainder of
```
