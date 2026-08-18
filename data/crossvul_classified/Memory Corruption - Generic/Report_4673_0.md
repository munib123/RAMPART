# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4673_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4673_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 412-452 of the vulnerable file.

  if (input & ST_NODEV) result |= kLinux_ST_NODEV;
  if (input & ST_NODIRATIME) result |= kLinux_ST_NODIRATIME;
  if (input & ST_NOEXEC) result |= kLinux_ST_NOEXEC;
  if (input & ST_RELATIME) result |= kLinux_ST_RELATIME;
  if (input & ST_SYNCHRONOUS) result |= kLinux_ST_SYNCHRONOUS;
#endif
  return result;
}

bool FromkLinuxSockAddr(const struct klinux_sockaddr *input,
                        socklen_t input_len, struct sockaddr *output,
                        socklen_t *output_len,
                        void (*abort_handler)(const char *)) {
  if (!input || !output || !output_len || input_len == 0) {
    output = nullptr;
    return false;
  }

  int16_t klinux_family = input->klinux_sa_family;
  if (klinux_family == kLinux_AF_UNIX) {
    struct klinux_sockaddr_un *klinux_sockaddr_un_in =
        const_cast<struct klinux_sockaddr_un *>(
            reinterpret_cast<const struct klinux_sockaddr_un *>(input));

    struct sockaddr_un sockaddr_un_out;
    sockaddr_un_out.sun_family = AF_UNIX;
    InitializeToZeroArray(sockaddr_un_out.sun_path);
    ReinterpretCopyArray(
        sockaddr_un_out.sun_path, klinux_sockaddr_un_in->klinux_sun_path,
        std::min(sizeof(sockaddr_un_out.sun_path),
                 sizeof(klinux_sockaddr_un_in->klinux_sun_path)));
    CopySockaddr(&sockaddr_un_out, sizeof(sockaddr_un_out), output, output_len);
  } else if (klinux_family == kLinux_AF_INET) {
    struct klinux_sockaddr_in *klinux_sockaddr_in_in =
        const_cast<struct klinux_sockaddr_in *>(
            reinterpret_cast<const struct klinux_sockaddr_in *>(input));

    struct sockaddr_in sockaddr_in_out;
    sockaddr_in_out.sin_family = AF_INET;
    sockaddr_in_out.sin_port = klinux_sockaddr_in_in->klinux_sin_port;
    InitializeToZeroSingle(&sockaddr_in_out.sin_addr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -429,6 +429,10 @@
 
   int16_t klinux_family = input->klinux_sa_family;
   if (klinux_family == kLinux_AF_UNIX) {
+    if (input_len < sizeof(struct klinux_sockaddr_un)) {
+      return false;
+    }
+
     struct klinux_sockaddr_un *klinux_sockaddr_un_in =
         const_cast<struct klinux_sockaddr_un *>(
             reinterpret_cast<const struct klinux_sockaddr_un *>(input));
@@ -442,6 +446,9 @@
                  sizeof(klinux_sockaddr_un_in->klinux_sun_path)));
     CopySockaddr(&sockaddr_un_out, sizeof(sockaddr_un_out), output, output_len);
   } else if (klinux_family == kLinux_AF_INET) {
+    if (input_len < sizeof(struct klinux_sockaddr_in)) {
+      return false;
+    }
     struct klinux_sockaddr_in *klinux_sockaddr_in_in =
         const_cast<struct klinux_sockaddr_in *>(
             reinterpret_cast<const struct klinux_sockaddr_in *>(input));
@@ -457,6 +464,10 @@
                          klinux_sockaddr_in_in->klinux_sin_zero);
     CopySockaddr(&sockaddr_in_out, sizeof(sockaddr_in_out), output, output_len);
   } else if (klinux_family == kLinux_AF_INET6) {
+    if (input_len < sizeof(struct klinux_sockaddr_in6)) {
+      return false;
+    }
+
     struct klinux_sockaddr_in6 *klinux_sockaddr_in6_in =
         const_cast<struct klinux_sockaddr_in6 *>(
             reinterpret_cast<const struct klinux_sockaddr_in6 *>(input));
```
