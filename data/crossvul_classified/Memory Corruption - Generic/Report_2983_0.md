# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2983_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2983_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2000-2040 of the vulnerable file.

		 * ptr &= ~3 which would reduce min_value by 3.)
		 */
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
				dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	default:
		/* other operators (e.g. MUL,LSH) produce non-pointer results */
		if (!env->allow_ptr_leaks)
			verbose(env, "R%d pointer arithmetic with %s operator prohibited\n",
				dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	}

	__update_reg_bounds(dst_reg);
	__reg_deduce_bounds(dst_reg);
	__reg_bound_offset(dst_reg);
	return 0;
}

static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
				      struct bpf_insn *insn,
				      struct bpf_reg_state *dst_reg,
				      struct bpf_reg_state src_reg)
{
	struct bpf_reg_state *regs = cur_regs(env);
	u8 opcode = BPF_OP(insn->code);
	bool src_known, dst_known;
	s64 smin_val, smax_val;
	u64 umin_val, umax_val;

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		/* 32-bit ALU ops are (32,32)->64 */
		coerce_reg_to_size(dst_reg, 4);
		coerce_reg_to_size(&src_reg, 4);
	}
	smin_val = src_reg.smin_value;
	smax_val = src_reg.smax_value;
	umin_val = src_reg.umin_value;
	umax_val = src_reg.umax_value;
	src_known = tnum_is_const(src_reg.var_off);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2017,6 +2017,10 @@
 	return 0;
 }
 
+/* WARNING: This function does calculations on 64-bit values, but the actual
+ * execution may occur on 32-bit values. Therefore, things like bitshifts
+ * need extra checks in the 32-bit case.
+ */
 static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 				      struct bpf_insn *insn,
 				      struct bpf_reg_state *dst_reg,
@@ -2027,12 +2031,8 @@
 	bool src_known, dst_known;
 	s64 smin_val, smax_val;
 	u64 umin_val, umax_val;
-
-	if (BPF_CLASS(insn->code) != BPF_ALU64) {
-		/* 32-bit ALU ops are (32,32)->64 */
-		coerce_reg_to_size(dst_reg, 4);
-		coerce_reg_to_size(&src_reg, 4);
-	}
+	u64 insn_bitness = (BPF_CLASS(insn->code) == BPF_ALU64) ? 64 : 32;
+
 	smin_val = src_reg.smin_value;
 	smax_val = src_reg.smax_value;
 	umin_val = src_reg.umin_value;
@@ -2168,9 +2168,9 @@
 		__update_reg_bounds(dst_reg);
 		break;
 	case BPF_LSH:
-		if (umax_val > 63) {
-			/* Shifts greater than 63 are undefined.  This includes
-			 * shifts by a negative number.
+		if (umax_val >= insn_bitness) {
+			/* Shifts greater than 31 or 63 are undefined.
+			 * This includes shifts by a negative number.
 			 */
 			mark_reg_unknown(env, regs, insn->dst_reg);
 			break;
@@ -2196,9 +2196,9 @@
 		__update_reg_bounds(dst_reg);
 		break;
 	case BPF_RSH:
-		if (umax_val > 63) {
-			/* Shifts greater than 63 are undefined.  This includes
-			 * shifts by a negative number.
+		if (umax_val >= insn_bitness) {
+			/* Shifts greater than 31 or 63 are undefined.
+			 * This includes shifts by a negative number.
 			 */
 			mark_reg_unknown(env, regs, insn->dst_reg);
 			break;
@@ -2232,6 +2232,12 @@
 	default:
 		mark_reg_unknown(env, regs, insn->dst_reg);
 		break;
+	}
+
+	if (BPF_CLASS(insn->code) != BPF_ALU64) {
+		/* 32-bit ALU ops are (32,32)->32 */
+		coerce_reg_to_size(dst_reg, 4);
+		coerce_reg_to_size(&src_reg, 4);
 	}
 
 	__reg_deduce_bounds(dst_reg);
```
