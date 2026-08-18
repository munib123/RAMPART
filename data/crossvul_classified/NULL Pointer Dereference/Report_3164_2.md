# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3164_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3164_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-31 of the vulnerable file.

#ifndef R_ENDIAN_H
#define R_ENDIAN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Endian agnostic functions working on single byte. */

static inline ut8 r_read_ble8(const void *src) {
	return *(ut8 *)src;
}

static inline ut8 r_read_at_ble8(const void *src, size_t offset) {
	return r_read_ble8 (((const ut8*)src) + offset);
}

static inline void r_write_ble8(void *dest, ut8 val) {
	*(ut8 *)dest = val;
}

static inline void r_write_at_ble8(void *dest, ut8 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_ble8 (d, val);
}

/* Big Endian functions. */

static inline ut8 r_read_be8(const void *src) {
	return r_read_ble8 (src);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,9 @@
 /* Endian agnostic functions working on single byte. */
 
 static inline ut8 r_read_ble8(const void *src) {
+	if (!src) {
+		return UT8_MAX;
+	}
 	return *(ut8 *)src;
 }
 
@@ -114,6 +117,9 @@
 /* Little Endian functions. */
 
 static inline ut8 r_read_le8(const void *src) {
+	if (!src) {
+		return UT8_MAX;
+	}
 	return r_read_ble8 (src);
 }
 
@@ -130,11 +136,17 @@
 }
 
 static inline ut16 r_read_le16(const void *src) {
+	if (!src) {
+		return UT16_MAX;
+	}
 	const ut8 *s = (const ut8*)src;
 	return (((ut16)s[1]) << 8) | (((ut16)s[0]) << 0);
 }
 
 static inline ut16 r_read_at_le16(const void *src, size_t offset) {
+	if (!src) {
+		return UT16_MAX;
+	}
 	const ut8 *s = (const ut8*)src + offset;
 	return r_read_le16 (s);
 }
@@ -157,12 +169,18 @@
 }
 
 static inline ut32 r_read_le32(const void *src) {
+	if (!src) {
+		return UT32_MAX;
+	}
 	const ut8 *s = (const ut8*)src;
 	return (((ut32)s[3]) << 24) | (((ut32)s[2]) << 16) |
 		(((ut32)s[1]) << 8) | (((ut32)s[0]) << 0);
 }
 
 static inline ut32 r_read_at_le32(const void *src, size_t offset) {
+	if (!src) {
+		return UT32_MAX;
+	}
 	const ut8 *s = (const ut8*)src + offset;
 	return r_read_le32 (s);
 }
@@ -426,6 +444,7 @@
 	}
 	return 1;
 }
+
 #ifdef __cplusplus
 }
 #endif
```
