# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4665_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4665_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 45-85 of the vulnerable file.

int ecall_take_snapshot(char **output, uint64_t *output_len) {
  int result = 0;
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
                                                              input_len)) {
    asylo::primitives::TrustedPrimitives::BestEffortAbort(
        "ecall_restore: input found to not be in untrusted memory.");
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
@@ -62,9 +62,11 @@
 int ecall_restore(const char *input, uint64_t input_len, char **output,
                   uint64_t *output_len) {
   if (!asylo::primitives::TrustedPrimitives::IsOutsideEnclave(input,
-                                                              input_len)) {
+                                                              input_len) ||
+      !asylo::primitives::TrustedPrimitives::IsOutsideEnclave(
+          output_len, sizeof(uint64_t))) {
     asylo::primitives::TrustedPrimitives::BestEffortAbort(
-        "ecall_restore: input found to not be in untrusted memory.");
+        "ecall_restore: input/output found to not be in untrusted memory.");
   }
   int result = 0;
   size_t tmp_output_len;
```
