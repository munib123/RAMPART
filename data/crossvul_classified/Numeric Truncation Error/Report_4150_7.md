# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_7
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_7`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 235-275 of the vulnerable file.

  }                                                   \
  uniform_remaining--;                                \
  double X = uniform_result[uniform_remaining]

    // Each attempt is 95+% successful, and requires 1-2 normal + 1 uniform
    static constexpr int kReservedSamplesPerOutput = 256;

    const int64 num_alphas = alpha_t.NumElements();
    OP_REQUIRES(ctx, num_alphas > 0,
                errors::InvalidArgument(
                    "Input alpha should have non-zero element count, got: ",
                    num_alphas));
    const int64 samples_per_alpha = samples_shape.num_elements() / num_alphas;
    const auto alpha_flat = alpha_t.flat<T>().data();
    auto samples_flat = output->flat<T>().data();

    // We partition work first across alphas then across samples-per-alpha to
    // avoid a couple flops which can be done on a per-alpha basis.

    auto DoWork = [samples_per_alpha, num_alphas, &random, samples_flat,
                   alpha_flat](int start_output, int limit_output) {
      // Capturing "random" by-value would only make a copy for the _shared_
      // lambda.  Since we want to let each worker have its own copy, we pass
      // "random" by reference and explicitly do a copy assignment.

      using Eigen::numext::exp;
      using Eigen::numext::log;
      using Eigen::numext::log1p;
      using Eigen::numext::pow;

      Normal normal;
      Uniform uniform;
      typename Normal::ResultType norm_result;
      typename Uniform::ResultType uniform_result;
      for (int64 output_idx = start_output; output_idx < limit_output;
           /* output_idx incremented within inner loop below */) {
        int64 alpha_idx = output_idx / samples_per_alpha;

        // Instead of +alpha_idx for each sample, we offset the pointer once.
        T* const samples_alpha_offset = samples_flat + alpha_idx;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,7 +252,7 @@
     // avoid a couple flops which can be done on a per-alpha basis.
 
     auto DoWork = [samples_per_alpha, num_alphas, &random, samples_flat,
-                   alpha_flat](int start_output, int limit_output) {
+                   alpha_flat](int64 start_output, int64 limit_output) {
       // Capturing "random" by-value would only make a copy for the _shared_
       // lambda.  Since we want to let each worker have its own copy, we pass
       // "random" by reference and explicitly do a copy assignment.
```
