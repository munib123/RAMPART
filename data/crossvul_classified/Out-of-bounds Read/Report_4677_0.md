# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 4677_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4677_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 209-249 of the vulnerable file.

    mode = va_arg(ap, mode_t);
    va_end(ap);
  }

  return EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_open, pathname, TokLinuxFileStatusFlag(flags),
      TokLinuxFileModeFlag(mode));
}

int enc_untrusted_unlink(const char *pathname) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_unlink,
                                             pathname);
}

int enc_untrusted_rename(const char *oldpath, const char *newpath) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_rename,
                                             oldpath, newpath);
}

ssize_t enc_untrusted_read(int fd, void *buf, size_t count) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_read, fd, buf, count));
}

ssize_t enc_untrusted_write(int fd, const void *buf, size_t count) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_write, fd, buf, count));
}

int enc_untrusted_symlink(const char *target, const char *linkpath) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_symlink,
                                             target, linkpath);
}

ssize_t enc_untrusted_readlink(const char *pathname, char *buf, size_t bufsiz) {
  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
      asylo::system_call::kSYS_readlink, pathname, buf, bufsiz));
}

int enc_untrusted_truncate(const char *path, off_t length) {
  return EnsureInitializedAndDispatchSyscall(asylo::system_call::kSYS_truncate,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,8 +226,13 @@
 }
 
 ssize_t enc_untrusted_read(int fd, void *buf, size_t count) {
-  return static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
+  ssize_t ret = static_cast<ssize_t>(EnsureInitializedAndDispatchSyscall(
       asylo::system_call::kSYS_read, fd, buf, count));
+  if (ret != -1 && ret > count) {
+    ::asylo::primitives::TrustedPrimitives::BestEffortAbort(
+        "enc_untrusted_read: read result exceeds requested");
+  }
+  return ret;
 }
 
 ssize_t enc_untrusted_write(int fd, const void *buf, size_t count) {
```
