# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4409_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4409_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 5650-5691 of the vulnerable file.

		 */
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	} else {
		/* ANDing two positives gives a positive, so safe to
		 * cast result into s64.
		 */
		dst_reg->smin_value = dst_reg->umin_value;
		dst_reg->smax_value = dst_reg->umax_value;
	}
	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}

static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
	s32 smin_val = src_reg->smin_value;
	u32 umin_val = src_reg->umin_value;

	/* Assuming scalar64_min_max_or will be called so it is safe
	 * to skip updating register for known case.
	 */
	if (src_known && dst_known)
		return;

	/* We get our maximum from the var_off, and our minimum is the
	 * maximum of the operands' minima
	 */
	dst_reg->u32_min_value = max(dst_reg->u32_min_value, umin_val);
	dst_reg->u32_max_value = var32_off.value | var32_off.mask;
	if (dst_reg->s32_min_value < 0 || smin_val < 0) {
		/* Lose signed bounds when ORing negative numbers,
		 * ain't nobody got time for that.
		 */
		dst_reg->s32_min_value = S32_MIN;
		dst_reg->s32_max_value = S32_MAX;
	} else {
		/* ORing two positives gives a positive, so safe to
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5667,8 +5667,8 @@
 	bool src_known = tnum_subreg_is_const(src_reg->var_off);
 	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
 	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
-	s32 smin_val = src_reg->smin_value;
-	u32 umin_val = src_reg->umin_value;
+	s32 smin_val = src_reg->s32_min_value;
+	u32 umin_val = src_reg->u32_min_value;
 
 	/* Assuming scalar64_min_max_or will be called so it is safe
 	 * to skip updating register for known case.
@@ -5691,8 +5691,8 @@
 		/* ORing two positives gives a positive, so safe to
 		 * cast result into s64.
 		 */
-		dst_reg->s32_min_value = dst_reg->umin_value;
-		dst_reg->s32_max_value = dst_reg->umax_value;
+		dst_reg->s32_min_value = dst_reg->u32_min_value;
+		dst_reg->s32_max_value = dst_reg->u32_max_value;
 	}
 }
 
```
