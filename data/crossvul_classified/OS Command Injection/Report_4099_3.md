# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 4099_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4099_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 135-175 of the vulnerable file.

  #define strcasecmp stricmp
  #define strncasecmp strnicmp
  #define __WINDOWS__ 1

  #include <time.h>
  static inline struct tm *gmtime_r(const time_t *t, struct tm *r) { return (gmtime_s(r, t))? NULL : r; }
#endif

#if defined(EMSCRIPTEN) || defined(__linux__) || defined(__APPLE__) || defined(__GNU__) || defined(__ANDROID__) || defined(__QNX__) || defined(__sun)
  #define __BSD__ 0
  #define __UNIX__ 1
#endif
#if __KFBSD__ || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
  #define __BSD__ 1
  #define __UNIX__ 1
#endif
#if __WINDOWS__ || _WIN32
  #ifdef _MSC_VER
  /* Must be included before windows.h */
  #include <winsock2.h>
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #endif
  typedef int socklen_t;
  #undef USE_SOCKETS
  #define __WINDOWS__ 1
  #undef __UNIX__
  #undef __BSD__
#endif
#if __WINDOWS__ || _WIN32
  #define __addr_t_defined
  #include <windows.h>
#endif

#if defined(__APPLE__) && (__arm__ || __arm64__ || __aarch64__)
#define TARGET_OS_IPHONE 1
#else
#define TARGET_OS_IPHONE 0
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,6 +152,7 @@
   #ifdef _MSC_VER
   /* Must be included before windows.h */
   #include <winsock2.h>
+  #include <ws2tcpip.h>
   #ifndef WIN32_LEAN_AND_MEAN
   #define WIN32_LEAN_AND_MEAN
   #endif
```
