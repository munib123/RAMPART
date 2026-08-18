# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in c
**Pair ID:** 327_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `327_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.

//#define printf(...)  ets_printf(__VA_ARGS__)
#define PSTR(s) (__extension__({static const char __c[] PROGMEM = (s); &__c[0];}))
#define PGM_VOID_P const void *
static inline void* memcpy_P(void* dest, PGM_VOID_P src, size_t count) {
    const uint8_t* read = (const uint8_t*)(src);
    uint8_t* write = (uint8_t*)(dest);

    while (count)
    {
        *write++ = pgm_read_byte(read++);
        count--;
    }

    return dest;
}
static inline int strlen_P(const char *str) {
    int cnt = 0;
    while (pgm_read_byte(str++)) cnt++;
    return cnt;
}
#define printf(fmt, ...) do { static const char fstr[] PROGMEM = fmt; char rstr[sizeof(fmt)]; memcpy_P(rstr, fstr, sizeof(rstr)); ets_printf(rstr, ##__VA_ARGS__); } while (0)
#define strcpy_P(dst, src) do { static const char fstr[] PROGMEM = src; memcpy_P(dst, fstr, sizeof(src)); } while (0)

// Copied from ets_sys.h to avoid compile warnings
extern int ets_printf(const char *format, ...)  __attribute__ ((format (printf, 1, 2)));
extern int ets_putc(int);

// The network interface in WiFiClientSecure
extern int ax_port_read(int fd, uint8_t* buffer, size_t count);
extern int ax_port_write(int fd, uint8_t* buffer, size_t count);

// TODO: Why is this not being imported from <string.h>?
extern char *strdup(const char *orig);

#elif defined(WIN32)

/* Windows CE stuff */
#if defined(_WIN32_WCE)
#include <basetsd.h>
#define abort()                 exit(1)
#else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,6 +142,18 @@
     while (pgm_read_byte(str++)) cnt++;
     return cnt;
 }
+static inline int memcmp_P(const void *a1, const void *b1, size_t len) {
+    const uint8_t* a = (const uint8_t*)(a1);
+    uint8_t* b = (uint8_t*)(b1);
+    for (size_t i=0; i<len; i++) {
+        uint8_t d = pgm_read_byte(a) - pgm_read_byte(b);
+        if (d) return d;
+        a++;
+        b++;
+    }
+    return 0;
+}
+
 #define printf(fmt, ...) do { static const char fstr[] PROGMEM = fmt; char rstr[sizeof(fmt)]; memcpy_P(rstr, fstr, sizeof(rstr)); ets_printf(rstr, ##__VA_ARGS__); } while (0)
 #define strcpy_P(dst, src) do { static const char fstr[] PROGMEM = src; memcpy_P(dst, fstr, sizeof(src)); } while (0)
 
```
