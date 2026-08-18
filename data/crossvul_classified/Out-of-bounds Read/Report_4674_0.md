# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4674_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4674_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1308-1350 of the vulnerable file.

    return nullptr;
  }

  MessageWriter input;
  input.Push<int>(TokLinuxAfFamily(af));
  input.PushByReference(Extent{reinterpret_cast<const char *>(src), src_size});
  input.Push(size);
  MessageReader output;

  const auto status = NonSystemCallDispatcher(
      ::asylo::host_call::kInetNtopHandler, &input, &output);
  CheckStatusAndParamCount(status, output, "enc_untrusted_inet_ntop", 2);

  auto result = output.next();
  int klinux_errno = output.next<int>();
  if (result.empty()) {
    errno = FromkLinuxErrorNumber(klinux_errno);
    return nullptr;
  }

  memcpy(dst, result.data(),
         std::min(static_cast<size_t>(size),
                  static_cast<size_t>(INET6_ADDRSTRLEN)));
  return dst;
}

int enc_untrusted_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  klinux_sigset_t klinux_set;
  if (!TokLinuxSigset(set, &klinux_set)) {
    errno = EINVAL;
    return -1;
  }

  int klinux_how = TokLinuxSigMaskAction(how);
  if (klinux_how == -1) {
    errno = EINVAL;
    return -1;
  }

  MessageWriter input;
  input.Push<int>(klinux_how);
  input.Push<klinux_sigset_t>(klinux_set);
  MessageReader output;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1325,9 +1325,10 @@
     return nullptr;
   }
 
-  memcpy(dst, result.data(),
-         std::min(static_cast<size_t>(size),
-                  static_cast<size_t>(INET6_ADDRSTRLEN)));
+  memcpy(
+      dst, result.data(),
+      std::min({static_cast<size_t>(size), static_cast<size_t>(result.size()),
+                static_cast<size_t>(INET6_ADDRSTRLEN)}));
   return dst;
 }
 
```
