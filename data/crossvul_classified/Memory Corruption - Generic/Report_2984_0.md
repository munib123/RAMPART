# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2984_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2984_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2173-2226 of the vulnerable file.

			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value <<= umin_val;
			dst_reg->umax_value <<= umax_val;
		}
		if (src_known)
			dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
		else
			dst_reg->var_off = tnum_lshift(tnum_unknown, umin_val);
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	case BPF_RSH:
		if (umax_val > 63) {
			/* Shifts greater than 63 are undefined.  This includes
			 * shifts by a negative number.
			 */
			mark_reg_unknown(env, regs, insn->dst_reg);
			break;
		}
		/* BPF_RSH is an unsigned shift, so make the appropriate casts */
		if (dst_reg->smin_value < 0) {
			if (umin_val) {
				/* Sign bit will be cleared */
				dst_reg->smin_value = 0;
			} else {
				/* Lost sign bit information */
				dst_reg->smin_value = S64_MIN;
				dst_reg->smax_value = S64_MAX;
			}
		} else {
			dst_reg->smin_value =
				(u64)(dst_reg->smin_value) >> umax_val;
		}
		if (src_known)
			dst_reg->var_off = tnum_rshift(dst_reg->var_off,
						       umin_val);
		else
			dst_reg->var_off = tnum_rshift(tnum_unknown, umin_val);
		dst_reg->umin_value >>= umax_val;
		dst_reg->umax_value >>= umin_val;
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
	default:
		mark_reg_unknown(env, regs, insn->dst_reg);
		break;
	}

	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2190,20 +2190,22 @@
 			mark_reg_unknown(env, regs, insn->dst_reg);
 			break;
 		}
-		/* BPF_RSH is an unsigned shift, so make the appropriate casts */
-		if (dst_reg->smin_value < 0) {
-			if (umin_val) {
-				/* Sign bit will be cleared */
-				dst_reg->smin_value = 0;
-			} else {
-				/* Lost sign bit information */
-				dst_reg->smin_value = S64_MIN;
-				dst_reg->smax_value = S64_MAX;
-			}
-		} else {
-			dst_reg->smin_value =
-				(u64)(dst_reg->smin_value) >> umax_val;
-		}
+		/* BPF_RSH is an unsigned shift.  If the value in dst_reg might
+		 * be negative, then either:
+		 * 1) src_reg might be zero, so the sign bit of the result is
+		 *    unknown, so we lose our signed bounds
+		 * 2) it's known negative, thus the unsigned bounds capture the
+		 *    signed bounds
+		 * 3) the signed bounds cross zero, so they tell us nothing
+		 *    about the result
+		 * If the value in dst_reg is known nonnegative, then again the
+		 * unsigned bounts capture the signed bounds.
+		 * Thus, in all cases it suffices to blow away our signed bounds
+		 * and rely on inferring new ones from the unsigned bounds and
+		 * var_off of the result.
+		 */
+		dst_reg->smin_value = S64_MIN;
+		dst_reg->smax_value = S64_MAX;
 		if (src_known)
 			dst_reg->var_off = tnum_rshift(dst_reg->var_off,
 						       umin_val);
```
