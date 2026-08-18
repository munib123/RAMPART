# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_3
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_3`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 78-118 of the vulnerable file.


 private:
  bool reverse_;
};

namespace functor {

template <typename T>
struct NthElementFunctor<CPUDevice, T> {
  void operator()(OpKernelContext* context, const Tensor& input_tensor,
                  Tensor& output_tensor, int n, bool reverse) {
    const T* input = input_tensor.flat<T>().data();
    T* output = output_tensor.flat<T>().data();

    // Assume input_shape is [d1,d2,...dk], and output_shape is [d1,d2...dk-1],
    // then num_rows = d1*d2...dk-1, last_dim = dk.
    const int num_rows = output_tensor.NumElements();
    const int last_dim = input_tensor.dim_size(input_tensor.dims() - 1);

    // Allocate each row to different shard.
    auto SubNthElement = [&, input, output, last_dim, n](int start, int limit) {
      // std::nth_element would rearrange the array, so we need a new buffer.
      std::vector<T> buf(last_dim);

      for (int b = start; b < limit; ++b) {
        // Copy from one row of elements to buffer
        const T* input_start = input + b * last_dim;
        const T* input_end = input + (b + 1) * last_dim;
        std::copy(input_start, input_end, buf.begin());

        std::nth_element(buf.begin(), buf.begin() + n, buf.end());
        // The element placed in the nth position is exactly the element that
        // would occur in this position if the range was fully sorted.
        output[b] = buf[n];
      }
    };

    auto worker_threads = *(context->device()->tensorflow_cpu_worker_threads());
    // The average time complexity of partition-based nth_element (BFPRT) is
    // O(n), although the worst time complexity could be O(n^2). Here, 20 is a
    // empirical factor of cost_per_unit.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,7 +95,8 @@
     const int last_dim = input_tensor.dim_size(input_tensor.dims() - 1);
 
     // Allocate each row to different shard.
-    auto SubNthElement = [&, input, output, last_dim, n](int start, int limit) {
+    auto SubNthElement = [&, input, output, last_dim, n](int64 start,
+                                                         int64 limit) {
       // std::nth_element would rearrange the array, so we need a new buffer.
       std::vector<T> buf(last_dim);
 
```
