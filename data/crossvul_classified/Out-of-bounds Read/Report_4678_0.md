# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4678_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4678_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 964-1004 of the vulnerable file.

  }

  MessageWriter input;
  input.Push<int>(sockfd);
  input.Push<uint64_t>(len);
  input.Push<int>(klinux_flags);
  MessageReader output;
  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kRecvFromHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_recvfrom", 4);

  int result = output.next<int>();
  int klinux_errno = output.next<int>();
  // recvfrom() returns -1 on failure, with errno set to indicate the cause
  // of the error.
  if (result == -1) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return result;
  }

  auto buffer_received = output.next();
  memcpy(buf, buffer_received.data(), std::min(len, buffer_received.size()));

  // If |src_addr| is not NULL, and the underlying protocol provides the source
  // address, this source address is filled in. When |src_addr| is NULL, nothing
  // is filled in; in this case, |addrlen| is not used, and should also be NULL.
  if (src_addr != nullptr && addrlen != nullptr) {
    auto klinux_sockaddr_buf = output.next();
    const struct klinux_sockaddr *klinux_addr =
        klinux_sockaddr_buf.As<struct klinux_sockaddr>();
    FromkLinuxSockAddr(klinux_addr, klinux_sockaddr_buf.size(), src_addr,
                       addrlen, TrustedPrimitives::BestEffortAbort);
  }

  return result;
}

int enc_untrusted_select(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timeval *timeout) {
  struct klinux_fd_set klinux_readfds, klinux_writefds, klinux_exceptfds;
  struct kLinux_timeval klinux_timeout;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -981,6 +981,11 @@
     return result;
   }
 
+  if (result > len) {
+    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
+        "enc_untrusted_recvfrom: result exceeds requested");
+  }
+
   auto buffer_received = output.next();
   memcpy(buf, buffer_received.data(), std::min(len, buffer_received.size()));
 
```
