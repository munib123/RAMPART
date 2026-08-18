# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4679_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4679_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 47-87 of the vulnerable file.

  size_t tmp_output_len;
  try {
    result = asylo::TakeSnapshot(output, &tmp_output_len);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  if (output_len) {
    *output_len = static_cast<uint64_t>(tmp_output_len);
  }
  return result;
}

// Invokes the enclave restoring entry-point. Returns a non-zero error code on
// failure.
int ecall_restore(const char *input, uint64_t input_len, char **output,
                  uint64_t *output_len) {
  if (!asylo::primitives::TrustedPrimitives::IsOutsideEnclave(input,
                                                              input_len) ||
      !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(
          output_len, sizeof(uint64_t))) {
    asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "ecall_restore: input/output found to not be in untrusted memory.");
  }
  int result = 0;
  size_t tmp_output_len;
  try {
    result = asylo::Restore(input, static_cast<size_t>(input_len), output,
                            &tmp_output_len);
  } catch (...) {
    LOG(FATAL) << "Uncaught exception in enclave";
  }

  if (output_len) {
    *output_len = static_cast<uint64_t>(tmp_output_len);
  }
  return result;
}

// Invokes the enclave secure snapshot key transfer entry-point. Returns a
// non-zero error code on failure.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,7 +64,9 @@
   if (!asylo::primitives::TrustedPrimitives::IsOutsideEnclave(input,
                                                               input_len) ||
       !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(
-          output_len, sizeof(uint64_t))) {
+          output_len, sizeof(uint64_t)) ||
+      !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(output,
+                                                              *output_len)) {
     asylo::primitives::TrustedPrimitives::BestEffortAbort(
         "ecall_restore: input/output found to not be in untrusted memory.");
   }
```
