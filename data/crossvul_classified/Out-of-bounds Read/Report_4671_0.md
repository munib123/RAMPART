# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4671_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4671_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 271-311 of the vulnerable file.

      reinterpret_cast<SgxParams *>(untrusted_cache->Malloc(sizeof(SgxParams)));
  Cleanup clean_up(
      [sgx_params, untrusted_cache] { untrusted_cache->Free(sgx_params); });
  sgx_params->input_size = 0;
  sgx_params->input = nullptr;
  if (input) {
    sgx_params->input_size = input->MessageSize();
    if (sgx_params->input_size > 0) {
      // Allocate and copy data to |input_buffer|.
      sgx_params->input = untrusted_cache->Malloc(sgx_params->input_size);
      input->Serialize(const_cast<void *>(sgx_params->input));
    }
  }
  sgx_params->output_size = 0;
  sgx_params->output = nullptr;
  CHECK_OCALL(
      ocall_dispatch_untrusted_call(&ret, untrusted_selector, sgx_params));
  if (sgx_params->input) {
    untrusted_cache->Free(const_cast<void *>(sgx_params->input));
  }
  if (sgx_params->output) {
    // For the results obtained in |output_buffer|, copy them to |output|
    // before freeing the buffer.
    output->Deserialize(sgx_params->output, sgx_params->output_size);
    TrustedPrimitives::UntrustedLocalFree(sgx_params->output);
  }
  return PrimitiveStatus::OkStatus();
}

// For SGX, CreateThread() needs to exit the enclave by making an UntrustedCall
// to CreateThreadHandler, which makes an EnclaveCall to enter the enclave with
// the new thread and register it with the thread manager and execute the
// intended callback.
int TrustedPrimitives::CreateThread() {
  MessageWriter input;
  MessageReader output;
  PrimitiveStatus status =
      UntrustedCall(kSelectorCreateThread, &input, &output);
  if (!status.ok()) {
    DebugPuts("CreateThread failed.");
    return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,6 +288,11 @@
   if (sgx_params->input) {
     untrusted_cache->Free(const_cast<void *>(sgx_params->input));
   }
+  if (!TrustedPrimitives::IsOutsideEnclave(sgx_params->output,
+                                           sgx_params->output_size)) {
+    TrustedPrimitives::BestEffortAbort(
+        "UntrustedCall: sgx_param output should be in untrusted memory");
+  }
   if (sgx_params->output) {
     // For the results obtained in |output_buffer|, copy them to |output|
     // before freeing the buffer.
```
