# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4676_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4676_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1266-1306 of the vulnerable file.

  MessageWriter input;
  input.Push<int>(TokLinuxAfFamily(af));
  input.PushByReference(Extent{
      src, std::min(strlen(src) + 1, static_cast<size_t>(INET6_ADDRSTRLEN))});
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kInetPtonHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_inet_pton", 3);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return -1;
  }

  auto klinux_addr_buffer = output.next();
  size_t max_size = 0;
  if (af == AF_INET) {
    max_size = sizeof(struct in_addr);
  } else if (af == AF_INET6) {
    max_size = sizeof(struct in6_addr);
  }
  memcpy(dst, klinux_addr_buffer.data(),
         std::min(klinux_addr_buffer.size(), max_size));
  return result;
}

const char *enc_untrusted_inet_ntop(int af, const void *src, char *dst,
                                    socklen_t size) {
  if (!src || !dst) {
    errno = EFAULT;
    return nullptr;
  }
  size_t src_size = 0;
  if (af == AF_INET) {
    src_size = sizeof(struct in_addr);
  } else if (af == AF_INET6) {
    src_size = sizeof(struct in6_addr);
  } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1283,8 +1283,16 @@
   auto klinux_addr_buffer = output.next();
   size_t max_size = 0;
   if (af == AF_INET) {
+    if (klinux_addr_buffer.size() != sizeof(klinux_in_addr)) {
+      ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
+          "enc_untrusted_inet_pton: unexpected output size");
+    }
     max_size = sizeof(struct in_addr);
   } else if (af == AF_INET6) {
+    if (klinux_addr_buffer.size() != sizeof(klinux_in6_addr)) {
+      ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
+          "enc_untrusted_inet_pton: unexpected output size");
+    }
     max_size = sizeof(struct in6_addr);
   }
   memcpy(dst, klinux_addr_buffer.data(),
```
