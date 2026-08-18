# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4672_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4672_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 76-116 of the vulnerable file.

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kSysFutexWakeHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_sys_futex_wake", 2);
  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  return result;
}

int32_t *enc_untrusted_create_wait_queue() {
  MessageWriter input;
  MessageReader output;
  input.Push<uint64_t>(sizeof(int32_t));
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kLocalLifetimeAllocHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_create_wait_queue",
                           2);
  int32_t *queue = reinterpret_cast<int32_t *>(output.next<uintptr_t>());
  int klinux_errno = output.next<int>();
  if (queue == nullptr) {
    errno = FromkLinuxErrorNumber(klinux_errno);
  }
  enc_untrusted_disable_waiting(queue);
  return queue;
}

void enc_untrusted_destroy_wait_queue(int32_t *const queue) {
  // This is a no op on purpose. Wait queue pointers are now
  // registered to be freed on enclave exit.
}

void enc_untrusted_thread_wait(int32_t *const queue,
                               uint64_t timeout_microsec) {
  enc_untrusted_thread_wait_value(queue, kWaitQueueEnabled, timeout_microsec);
}

void enc_untrusted_notify(int32_t *const queue, int32_t num_threads) {
  enc_untrusted_sys_futex_wake(queue, num_threads);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,10 @@
   CheckStatusAndParamCount(status, output, "enc_untrusted_create_wait_queue",
                            2);
   int32_t *queue = reinterpret_cast<int32_t *>(output.next<uintptr_t>());
+  if (!TrustedPrimitives::IsOutsideEnclave(queue, sizeof(int32_t))) {
+    TrustedPrimitives::BestEffortAbort(
+        "enc_untrusted_create_wait_queue: queue should be in untrusted memory");
+  }
   int klinux_errno = output.next<int>();
   if (queue == nullptr) {
     errno = FromkLinuxErrorNumber(klinux_errno);
```
