# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4670_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4670_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 626-666 of the vulnerable file.

}

void *enc_untrusted_realloc(void *ptr, size_t size) {
  MessageWriter input;
  input.Push(reinterpret_cast<uint64_t>(ptr));
  input.Push(static_cast<uint64_t>(size));

  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(
          asylo::host_call::kReallocHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_realloc", 2);

  void *result = output.next<void *>();
  int klinux_errno = output.next<int>();

  // realloc only sets the errno (ENOMEM) when output pointer is null and a
  // non-zero |size| is provided.
  if (!result && size != 0) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

uint32_t enc_untrusted_sleep(uint32_t seconds) {
  MessageWriter input;
  input.Push<uint32_t>(seconds);
  MessageReader output;
  asylo::primitives::PrimitiveStatus status =
      asylo::host_call::NonSystemCallDispatcher(asylo::host_call::kSleepHandler,
                                                &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sleep", 2);

  // Returns sleep's return value directly since it doesn't set errno.
  return output.next<uint32_t>();
}

int enc_untrusted_nanosleep(const struct timespec *req, struct timespec *rem) {
  struct kLinux_timespec klinux_req;
  if (!TokLinuxtimespec(req, &klinux_req)) {
    errno = EINVAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -644,6 +644,12 @@
   if (!result && size != 0) {
     errno = FromkLinuxErrorNumber(klinux_errno);
   }
+
+  if (!::asylo::primitives::TrustedPrimitives::IsOutsideEnclave(result, size)) {
+    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
+        "enc_untrusted_realloc: realloc result should be in untrusted "
+        "memory");
+  }
   return result;
 }
 
```
