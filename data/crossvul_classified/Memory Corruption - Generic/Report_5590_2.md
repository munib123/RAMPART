# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5590_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5590_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 97-137 of the vulnerable file.

		return -1;

	nc = 0;
	for (t = utf8_table; t->cmask && maxlen; t++, maxlen--) {
		nc++;
		if (l <= t->lmask) {
			c = t->shift;
			*s = (u8) (t->cval | (l >> c));
			while (c > 0) {
				c -= 6;
				s++;
				*s = (u8) (0x80 | ((l >> c) & 0x3F));
			}
			return nc;
		}
	}
	return -1;
}
EXPORT_SYMBOL(utf32_to_utf8);

int utf8s_to_utf16s(const u8 *s, int len, wchar_t *pwcs)
{
	u16 *op;
	int size;
	unicode_t u;

	op = pwcs;
	while (*s && len > 0) {
		if (*s & 0x80) {
			size = utf8_to_utf32(s, len, &u);
			if (size < 0)
				return -EINVAL;

			if (u >= PLANE_SIZE) {
				u -= PLANE_SIZE;
				*op++ = (wchar_t) (SURROGATE_PAIR |
						((u >> 10) & SURROGATE_BITS));
				*op++ = (wchar_t) (SURROGATE_PAIR |
						SURROGATE_LOW |
						(u & SURROGATE_BITS));
			} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,34 +114,57 @@
 }
 EXPORT_SYMBOL(utf32_to_utf8);
 
-int utf8s_to_utf16s(const u8 *s, int len, wchar_t *pwcs)
+static inline void put_utf16(wchar_t *s, unsigned c, enum utf16_endian endian)
+{
+	switch (endian) {
+	default:
+		*s = (wchar_t) c;
+		break;
+	case UTF16_LITTLE_ENDIAN:
+		*s = __cpu_to_le16(c);
+		break;
+	case UTF16_BIG_ENDIAN:
+		*s = __cpu_to_be16(c);
+		break;
+	}
+}
+
+int utf8s_to_utf16s(const u8 *s, int len, enum utf16_endian endian,
+		wchar_t *pwcs, int maxlen)
 {
 	u16 *op;
 	int size;
 	unicode_t u;
 
 	op = pwcs;
-	while (*s && len > 0) {
+	while (len > 0 && maxlen > 0 && *s) {
 		if (*s & 0x80) {
 			size = utf8_to_utf32(s, len, &u);
 			if (size < 0)
 				return -EINVAL;
-
-			if (u >= PLANE_SIZE) {
-				u -= PLANE_SIZE;
-				*op++ = (wchar_t) (SURROGATE_PAIR |
-						((u >> 10) & SURROGATE_BITS));
-				*op++ = (wchar_t) (SURROGATE_PAIR |
-						SURROGATE_LOW |
-						(u & SURROGATE_BITS));
-			} else {
-				*op++ = (wchar_t) u;
-			}
 			s += size;
 			len -= size;
+
+			if (u >= PLANE_SIZE) {
+				if (maxlen < 2)
+					break;
+				u -= PLANE_SIZE;
+				put_utf16(op++, SURROGATE_PAIR |
+						((u >> 10) & SURROGATE_BITS),
+						endian);
+				put_utf16(op++, SURROGATE_PAIR |
+						SURROGATE_LOW |
+						(u & SURROGATE_BITS),
+						endian);
+				maxlen -= 2;
+			} else {
+				put_utf16(op++, u, endian);
+				maxlen--;
+			}
 		} else {
-			*op++ = *s++;
+			put_utf16(op++, *s++, endian);
 			len--;
+			maxlen--;
 		}
 	}
 	return op - pwcs;
```
