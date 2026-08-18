# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_4
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_4`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 53-94 of the vulnerable file.

  void operator()(OpKernelContext* ctx, const CPUDevice& d, int64 num_batches,
                  int64 samples_per_batch, int64 num_elements,
                  typename TTypes<T>::ConstFlat means,
                  typename TTypes<T>::ConstFlat stddevs,
                  typename TTypes<T>::ConstFlat minvals,
                  typename TTypes<T>::ConstFlat maxvals,
                  const random::PhiloxRandom& gen,
                  typename TTypes<T>::Flat output) {
    // The randn rejection sampling is used when the mean and at least this many
    // standard deviations are inside the bounds.
    // The uniform proposal samplers become less efficient as the bounds are
    // further from the mean, the reverse is true for the randn sampler.
    // This number was chosen by empirical benchmarking. If modified, the
    // benchmarks in parameterized_truncated_normal_op_test should also be
    // changed.
    const T kStdDevsInsideBoundsToUseRandnSampler = T(1.3);
    auto worker_threads = *(ctx->device()->tensorflow_cpu_worker_threads());

    auto do_work = [samples_per_batch, num_elements, &ctx, &means, &stddevs,
                    &minvals, &maxvals, &gen, &output,
                    kStdDevsInsideBoundsToUseRandnSampler](int start_batch,
                                                           int limit_batch) {
      // Capturing "gen" by-value would only make a copy for the _shared_
      // lambda.  Since we want to let each worker have its own copy, we pass
      // "gen" by reference and explicitly do a copy assignment here.
      random::PhiloxRandom gen_copy = gen;
      // Skip takes units of 128 bytes.  +3 is so rounding doesn't lead to
      // us using the same state in different batches.
      // The sample from each iteration uses 2 random numbers.
      gen_copy.Skip(start_batch * 2 * kMaxIterations * (samples_per_batch + 3) /
                    4);
      using Uniform = random::UniformDistribution<random::PhiloxRandom, T>;
      Uniform dist;
      using Normal = random::NormalDistribution<random::PhiloxRandom, T>;
      Normal normal_dist;

      // Vectorized intermediate calculations for uniform rejection sampling.
      // We always generate at most 4 samples.
      Eigen::array<T, 4> z;
      Eigen::array<T, 4> g;

      for (int64 b = start_batch; b < limit_batch; ++b) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,8 +70,8 @@
 
     auto do_work = [samples_per_batch, num_elements, &ctx, &means, &stddevs,
                     &minvals, &maxvals, &gen, &output,
-                    kStdDevsInsideBoundsToUseRandnSampler](int start_batch,
-                                                           int limit_batch) {
+                    kStdDevsInsideBoundsToUseRandnSampler](int64 start_batch,
+                                                           int64 limit_batch) {
       // Capturing "gen" by-value would only make a copy for the _shared_
       // lambda.  Since we want to let each worker have its own copy, we pass
       // "gen" by reference and explicitly do a copy assignment here.
@@ -333,8 +333,8 @@
 
     auto do_work = [num_batches, samples_per_batch, &ctx, &bcast, &means,
                     &stddevs, &minvals, &maxvals, &gen, &output,
-                    kStdDevsInsideBoundsToUseRandnSampler](int start_output,
-                                                           int limit_output) {
+                    kStdDevsInsideBoundsToUseRandnSampler](int64 start_output,
+                                                           int64 limit_output) {
       // Capturing "gen" by-value would only make a copy for the _shared_
       // lambda.  Since we want to let each worker have its own copy, we pass
       // "gen" by reference and explicitly do a copy assignment here.
```
