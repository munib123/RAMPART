# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1115_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1115_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 42-83 of the vulnerable file.

// segment_ids_shape: shape of 'segment_ids' tensor.
// segment_ids: unsorted map from input to output segment ids at which to
//                perform segment sum operation.
// data_size: size of input data tensor.
// data: input data tensor.
// output: output reshaped to {output_rows, output.size/output_rows}
template <typename T, typename Index>
struct SegmentSumFunctor {
  void operator()(OpKernelContext* ctx, const GPUDevice& d,
                  const Index output_rows, const TensorShape& segment_ids_shape,
                  typename TTypes<Index>::ConstFlat segment_ids,
                  const Index data_size, const T* data,
                  typename TTypes<T, 2>::Tensor output);
};

#endif

template <typename Device, typename T, typename Index, typename InitialValueF,
          typename ReductionF>
struct UnsortedSegmentFunctor {
  void operator()(OpKernelContext* ctx, const Index num_segments,
                  const TensorShape& segment_ids_shape,
                  typename TTypes<Index>::ConstFlat segment_ids,
                  const Index data_size, const T* data,
                  typename TTypes<T, 2>::Tensor output);
};

#if GOOGLE_CUDA || TENSORFLOW_USE_ROCM
// reduction functors for the gpu
template <typename T>
struct SumOpGpu {
  EIGEN_DEVICE_FUNC EIGEN_STRONG_INLINE void operator()(T* dest,
                                                        const T& value) {
    GpuAtomicAdd(dest, value);
  }
};

template <typename T>
struct ProdOpGpu {
  EIGEN_DEVICE_FUNC EIGEN_STRONG_INLINE void operator()(T* dest,
                                                        const T& value) {
    GpuAtomicMul(dest, value);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,10 +59,9 @@
 template <typename Device, typename T, typename Index, typename InitialValueF,
           typename ReductionF>
 struct UnsortedSegmentFunctor {
-  void operator()(OpKernelContext* ctx, const Index num_segments,
-                  const TensorShape& segment_ids_shape,
+  void operator()(OpKernelContext* ctx, const TensorShape& segment_ids_shape,
                   typename TTypes<Index>::ConstFlat segment_ids,
-                  const Index data_size, const T* data,
+                  typename TTypes<T, 2>::ConstTensor data,
                   typename TTypes<T, 2>::Tensor output);
 };
 
```
