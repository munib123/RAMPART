# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 143_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `143_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 397-439 of the vulnerable file.

				goto err;
			}
			if (!(table = calloc (count, sizeof (ut32)))) {
				goto err;
			}
			int i = 0;
			op->len += n;
			for (i = 0; i < count; i++) {
				n = read_u32_leb128 (buf + op->len, buf + buf_len, &table[i]);
				if (!(op->len + n <= buf_len)) {
					goto beach;
				}
				op->len += n;
			}
			n = read_u32_leb128 (buf + op->len, buf + buf_len, &def);
			if (!(n > 0 && n + op->len < buf_len)) {
				goto beach;
			}
			op->len += n;
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d ", opdef->txt, count);
			for (i = 0; i < count && strlen (op->txt) + 10 < R_ASM_BUFSIZE; i++) {
				int optxtlen = strlen (op->txt);
				snprintf (op->txt + optxtlen, R_ASM_BUFSIZE - optxtlen, "%d ", table[i]);
			}
			snprintf (op->txt + strlen (op->txt), R_ASM_BUFSIZE, "%d", def);
			free (table);
			break;
			beach:
			free (table);
			goto err;
		}
		break;
	case WASM_OP_CALLINDIRECT:
		{
			ut32 val = 0, reserved = 0;
			size_t n = read_u32_leb128 (buf + 1, buf + buf_len, &val);
			if (!(n > 0 && n < buf_len)) goto err;
			op->len += n;
			n = read_u32_leb128 (buf + op->len, buf + buf_len, &reserved);
			if (!(n == 1 && op->len + n <= buf_len)) goto err;
			reserved &= 0x1;
			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d %d", opdef->txt, val, reserved);
			op->len += n;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -414,14 +414,20 @@
 			}
 			op->len += n;
 			snprintf (op->txt, R_ASM_BUFSIZE, "%s %d ", opdef->txt, count);
-			for (i = 0; i < count && strlen (op->txt) + 10 < R_ASM_BUFSIZE; i++) {
-				int optxtlen = strlen (op->txt);
-				snprintf (op->txt + optxtlen, R_ASM_BUFSIZE - optxtlen, "%d ", table[i]);
-			}
-			snprintf (op->txt + strlen (op->txt), R_ASM_BUFSIZE, "%d", def);
+			char *txt = op->txt;
+			int txtLen = strlen (op->txt);
+			int txtLeft = R_ASM_BUFSIZE - txtLen;
+			txt += txtLen;
+			for (i = 0; i < count && txtLen + 10 < R_ASM_BUFSIZE; i++) {
+				snprintf (txt, txtLeft, "%d ", table[i]);
+				txtLen = strlen (txt);
+				txt += txtLen;
+				txtLeft -= txtLen;
+			}
+			snprintf (txt, txtLeft - 1, "%d", def);
 			free (table);
 			break;
-			beach:
+		beach:
 			free (table);
 			goto err;
 		}
```
