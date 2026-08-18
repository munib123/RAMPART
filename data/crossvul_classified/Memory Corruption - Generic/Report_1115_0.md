# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 1115_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1115_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 359-400 of the vulnerable file.

                          SegmentSumGPUOp<type, index_type>)

#define REGISTER_GPU_SORTED_KERNELS_ALL(type) \
  REGISTER_GPU_SORTED_KERNELS(type, int32);   \
  REGISTER_GPU_SORTED_KERNELS(type, int64);

TF_CALL_GPU_NUMBER_TYPES(REGISTER_GPU_SORTED_KERNELS_ALL);
#undef REGISTER_GPU_SORTED_KERNELS
#undef REGISTER_GPU_SORTED_KERNELS_ALL
#endif  // GOOGLE_CUDA || TENSORFLOW_USE_ROCM

// ____________________________________________________________________________
// Unsorted segment reduction ops.

namespace functor {

// The ReductionFunctor implementation for CPU.
template <typename T, typename Index, typename InitialValueF,
          typename ReductionF>
struct UnsortedSegmentFunctor<CPUDevice, T, Index, InitialValueF, ReductionF> {
  void operator()(OpKernelContext* ctx, const Index num_segments,
                  const TensorShape& segment_ids_shape,
                  typename TTypes<Index>::ConstFlat segment_ids,
                  const Index data_size, const T* data,
                  typename TTypes<T, 2>::Tensor output) {
    output.setConstant(InitialValueF()());
    if (data_size == 0) {
      return;
    }
    const int64 N = segment_ids.dimension(0);
    ReductionF reduction;
    auto data_flat = typename TTypes<T, 2>::ConstTensor(data, N, data_size / N);
    for (int64 i = 0; i < N; ++i) {
      Index j = internal::SubtleMustCopy(segment_ids(i));
      if (j < 0) {
        continue;
      }
      OP_REQUIRES(ctx, FastBoundsCheck(j, num_segments),
                  errors::InvalidArgument(
                      "segment_ids", SliceDebugString(segment_ids_shape, i),
                      " = ", j, " is out of range [0, ", num_segments, ")"));
      reduction(data_flat.template chip<0>(i), output.template chip<0>(j));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -376,18 +376,17 @@
 template <typename T, typename Index, typename InitialValueF,
           typename ReductionF>
 struct UnsortedSegmentFunctor<CPUDevice, T, Index, InitialValueF, ReductionF> {
-  void operator()(OpKernelContext* ctx, const Index num_segments,
-                  const TensorShape& segment_ids_shape,
+  void operator()(OpKernelContext* ctx, const TensorShape& segment_ids_shape,
                   typename TTypes<Index>::ConstFlat segment_ids,
-                  const Index data_size, const T* data,
+                  typename TTypes<T, 2>::ConstTensor data,
                   typename TTypes<T, 2>::Tensor output) {
     output.setConstant(InitialValueF()());
-    if (data_size == 0) {
+    if (data.size() == 0) {
       return;
     }
     const int64 N = segment_ids.dimension(0);
+    const int64 num_segments = output.dimension(0);
     ReductionF reduction;
-    auto data_flat = typename TTypes<T, 2>::ConstTensor(data, N, data_size / N);
     for (int64 i = 0; i < N; ++i) {
       Index j = internal::SubtleMustCopy(segment_ids(i));
       if (j < 0) {
@@ -397,7 +396,7 @@
                   errors::InvalidArgument(
                       "segment_ids", SliceDebugString(segment_ids_shape, i),
                       " = ", j, " is out of range [0, ", num_segments, ")"));
-      reduction(data_flat.template chip<0>(i), output.template chip<0>(j));
+      reduction(data.template chip<0>(i), output.template chip<0>(j));
     }
   }
 };
@@ -485,7 +484,7 @@
       return;
     }
     const auto segment_flat = segment_ids.flat<Index>();
-    const Index output_rows = internal::SubtleMustCopy(static_cast<Index>(
+    const int64 output_rows = internal::SubtleMustCopy(static_cast<int64>(
         num_segments.dtype() == DT_INT32 ? num_segments.scalar<int32>()()
                                          : num_segments.scalar<int64>()()));
     OP_REQUIRES(context, output_rows >= 0,
@@ -499,9 +498,9 @@
     Tensor* output = nullptr;
     OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &output));
     auto output_flat = output->flat_outer_dims<T>();
-    auto data_ptr = data.template flat<T>().data();
-    reduction_functor_(context, output_rows, segment_ids.shape(), segment_flat,
-                       data.NumElements(), data_ptr, output_flat);
+    auto data_flat = data.flat_inner_outer_dims<T, 2>(segment_ids.dims() - 1);
+    reduction_functor_(context, segment_ids.shape(), segment_flat, data_flat,
+                       output_flat);
   }
 
  protected:
```
