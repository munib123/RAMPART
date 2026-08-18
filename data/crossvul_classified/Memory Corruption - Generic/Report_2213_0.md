# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2213_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2213_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2-46 of the vulnerable file.

 *  LZO1X Decompressor from LZO
 *
 *  Copyright (C) 1996-2012 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for Linux kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */

#ifndef STATIC
#include <linux/module.h>
#include <linux/kernel.h>
#endif
#include <asm/unaligned.h>
#include <linux/lzo.h>
#include "lzodefs.h"

#define HAVE_IP(x)      ((size_t)(ip_end - ip) >= (size_t)(x))
#define HAVE_OP(x)      ((size_t)(op_end - op) >= (size_t)(x))
#define NEED_IP(x)      if (!HAVE_IP(x)) goto input_overrun
#define NEED_OP(x)      if (!HAVE_OP(x)) goto output_overrun
#define TEST_LB(m_pos)  if ((m_pos) < out) goto lookbehind_overrun

int lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
			  unsigned char *out, size_t *out_len)
{
	unsigned char *op;
	const unsigned char *ip;
	size_t t, next;
	size_t state = 0;
	const unsigned char *m_pos;
	const unsigned char * const ip_end = in + in_len;
	unsigned char * const op_end = out + *out_len;

	op = out;
	ip = in;

	if (unlikely(in_len < 3))
		goto input_overrun;
	if (*ip > 17) {
		t = *ip++ - 17;
		if (t < 4) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,11 +19,31 @@
 #include <linux/lzo.h>
 #include "lzodefs.h"
 
-#define HAVE_IP(x)      ((size_t)(ip_end - ip) >= (size_t)(x))
-#define HAVE_OP(x)      ((size_t)(op_end - op) >= (size_t)(x))
-#define NEED_IP(x)      if (!HAVE_IP(x)) goto input_overrun
-#define NEED_OP(x)      if (!HAVE_OP(x)) goto output_overrun
-#define TEST_LB(m_pos)  if ((m_pos) < out) goto lookbehind_overrun
+#define HAVE_IP(t, x)					\
+	(((size_t)(ip_end - ip) >= (size_t)(t + x)) &&	\
+	 (((t + x) >= t) && ((t + x) >= x)))
+
+#define HAVE_OP(t, x)					\
+	(((size_t)(op_end - op) >= (size_t)(t + x)) &&	\
+	 (((t + x) >= t) && ((t + x) >= x)))
+
+#define NEED_IP(t, x)					\
+	do {						\
+		if (!HAVE_IP(t, x))			\
+			goto input_overrun;		\
+	} while (0)
+
+#define NEED_OP(t, x)					\
+	do {						\
+		if (!HAVE_OP(t, x))			\
+			goto output_overrun;		\
+	} while (0)
+
+#define TEST_LB(m_pos)					\
+	do {						\
+		if ((m_pos) < out)			\
+			goto lookbehind_overrun;	\
+	} while (0)
 
 int lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
 			  unsigned char *out, size_t *out_len)
@@ -58,14 +78,14 @@
 					while (unlikely(*ip == 0)) {
 						t += 255;
 						ip++;
-						NEED_IP(1);
+						NEED_IP(1, 0);
 					}
 					t += 15 + *ip++;
 				}
 				t += 3;
 copy_literal_run:
 #if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
-				if (likely(HAVE_IP(t + 15) && HAVE_OP(t + 15))) {
+				if (likely(HAVE_IP(t, 15) && HAVE_OP(t, 15))) {
 					const unsigned char *ie = ip + t;
 					unsigned char *oe = op + t;
 					do {
@@ -81,8 +101,8 @@
 				} else
 #endif
 				{
-					NEED_OP(t);
-					NEED_IP(t + 3);
+					NEED_OP(t, 0);
+					NEED_IP(t, 3);
 					do {
 						*op++ = *ip++;
 					} while (--t > 0);
@@ -95,7 +115,7 @@
 				m_pos -= t >> 2;
 				m_pos -= *ip++ << 2;
 				TEST_LB(m_pos);
-				NEED_OP(2);
+				NEED_OP(2, 0);
 				op[0] = m_pos[0];
 				op[1] = m_pos[1];
 				op += 2;
@@ -119,10 +139,10 @@
 				while (unlikely(*ip == 0)) {
 					t += 255;
 					ip++;
-					NEED_IP(1);
+					NEED_IP(1, 0);
 				}
 				t += 31 + *ip++;
-				NEED_IP(2);
+				NEED_IP(2, 0);
 			}
 			m_pos = op - 1;
 			next = get_unaligned_le16(ip);
@@ -137,10 +157,10 @@
 				while (unlikely(*ip == 0)) {
 					t += 255;
 					ip++;
-					NEED_IP(1);
+					NEED_IP(1, 0);
 				}
 				t += 7 + *ip++;
-				NEED_IP(2);
+				NEED_IP(2, 0);
 			}
 			next = get_unaligned_le16(ip);
 			ip += 2;
@@ -154,7 +174,7 @@
 #if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
 		if (op - m_pos >= 8) {
 			unsigned char *oe = op + t;
-			if (likely(HAVE_OP(t + 15))) {
+			if (likely(HAVE_OP(t, 15))) {
 				do {
 					COPY8(op, m_pos);
 					op += 8;
@@ -164,7 +184,7 @@
 					m_pos += 8;
 				} while (op < oe);
 				op = oe;
-				if (HAVE_IP(6)) {
+				if (HAVE_IP(6, 0)) {
 					state = next;
 					COPY4(op, ip);
 					op += next;
@@ -172,7 +192,7 @@
 					continue;
 				}
 			} else {
-				NEED_OP(t);
+				NEED_OP(t, 0);
 				do {
 					*op++ = *m_pos++;
 				} while (op < oe);
@@ -181,7 +201,7 @@
 #endif
 		{
 			unsigned char *oe = op + t;
-			NEED_OP(t);
+			NEED_OP(t, 0);
 			op[0] = m_pos[0];
 			op[1] = m_pos[1];
 			op += 2;
@@ -194,15 +214,15 @@
 		state = next;
 		t = next;
 #if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
-		if (likely(HAVE_IP(6) && HAVE_OP(4))) {
+		if (likely(HAVE_IP(6, 0) && HAVE_OP(4, 0))) {
 			COPY4(op, ip);
 			op += t;
 			ip += t;
 		} else
 #endif
 		{
-			NEED_IP(t + 3);
-			NEED_OP(t);
+			NEED_IP(t, 3);
+			NEED_OP(t, 0);
 			while (t > 0) {
 				*op++ = *ip++;
 				t--;
```
