# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 517_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `517_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 1-27 of the vulnerable file.

#include "util.h"

#include <climits>
#include <cstdio>

#include "Enclave_t.h"

int printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
  return ret;
}

/** From https://stackoverflow.com/a/8362718 */
std::string string_format(const std::string &fmt, ...) {
    int size=BUFSIZ;
    std::string str;
    va_list ap;
    while (1) {
        str.resize(size);
        va_start(ap, fmt);
        int n = vsnprintf(&str[0], size, fmt.c_str(), ap);
        va_end(ap);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 #include <cstdio>
 
 #include "Enclave_t.h"
+#include "sgx_lfence.h"
 
 int printf(const char *fmt, ...) {
   char buf[BUFSIZ] = {'\0'};
@@ -36,6 +37,14 @@
 
 void exit(int exit_code) {
   ocall_exit(exit_code);
+}
+
+void ocall_malloc(size_t size, uint8_t **ret) {
+  unsafe_ocall_malloc(size, ret);
+
+  // Guard against overwriting enclave memory
+  assert(sgx_is_outside_enclave(*ret, size) == 1);
+  sgx_lfence();
 }
 
 void print_bytes(uint8_t *ptr, uint32_t len) {
```
