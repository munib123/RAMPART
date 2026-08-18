# CrossVul Fix Pair: Numeric Truncation Error in cpp
**Pair ID:** 4150_6
**Vulnerability Class:** Numeric Truncation Error
**CWE:** CWE-197
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4150_6`)

## Vulnerability Information & PoC

## Description
Numeric Truncation Error - When a primitive is cast to a smaller primitive, the high order bits of the large value are lost in the conversion, potentially resulting in an unexpected value that is not equal to the original va...

## Vulnerable Code
```cpp
Lines 80-120 of the vulnerable file.

    //
    // This algorithm runs in O(rate) time, and will require O(rate)
    // uniform variates.
    //
    // If rate >= 10 we use a transformation-rejection algorithm from
    // pairs of uniform random variables due to Hormann.
    // http://www.sciencedirect.com/science/article/pii/0167668793909974
    //
    // The algorithm has an acceptance rate of ~89% for the smallest rate
    // (~10),
    // and higher accept rates for higher rate, so runtime is
    // O(NumRate * NumSamples * k) with k ~ 1 / 0.89.
    //
    // We partition work first across rates then across
    // samples-per-rate to
    // avoid a couple flops which can be done on a per-rate basis.

    typedef random::UniformDistribution<random::PhiloxRandom, CT> Uniform;

    auto DoWork = [num_samples, num_rate, &rng, samples_flat, rate_flat](
                      int start_output, int limit_output) {
      // Capturing "rng" by value would only make a copy for the _shared_
      // lambda.  Since we want to let each worker have its own copy, we pass
      // "rng" by reference and explicitly do a copy assignment.

      Uniform uniform;
      typename Uniform::ResultType uniform_result;
      for (int64 output_idx = start_output; output_idx < limit_output;
           /* output_idx incremented within inner loop below */) {
        const int64 rate_idx = output_idx / num_samples;

        // Several calculations can be done on a per-rate basis.
        const CT rate = CT(rate_flat[rate_idx]);

        auto samples_rate_output = samples_flat + rate_idx;

        if (rate < CT(10)) {
          // Knuth's algorithm for generating Poisson random variates.
          // Given a Poisson process, the time between events is exponentially
          // distributed. If we have a Poisson process with rate lambda, then,
          // the time between events is distributed Exp(lambda). If X ~
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,7 @@
     typedef random::UniformDistribution<random::PhiloxRandom, CT> Uniform;
 
     auto DoWork = [num_samples, num_rate, &rng, samples_flat, rate_flat](
-                      int start_output, int limit_output) {
+                      int64 start_output, int64 limit_output) {
       // Capturing "rng" by value would only make a copy for the _shared_
       // lambda.  Since we want to let each worker have its own copy, we pass
       // "rng" by reference and explicitly do a copy assignment.
```
