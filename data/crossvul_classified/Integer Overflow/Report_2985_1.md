# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 2985_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2985_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1802-1842 of the vulnerable file.

static bool signed_add_overflows(s64 a, s64 b)
{
	/* Do the add in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a + (u64)b);

	if (b < 0)
		return res > a;
	return res < a;
}

static bool signed_sub_overflows(s64 a, s64 b)
{
	/* Do the sub in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a - (u64)b);

	if (b < 0)
		return res < a;
	return res > a;
}

/* Handles arithmetic on a pointer and a scalar: computes new min/max and var_off.
 * Caller should also handle BPF_MOV case separately.
 * If we return -EACCES, caller may want to try again treating pointer as a
 * scalar.  So we only emit a diagnostic if !env->allow_ptr_leaks.
 */
static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg)
{
	struct bpf_reg_state *regs = cur_regs(env), *dst_reg;
	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value,
	    smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value,
	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;

	dst_reg = &regs[dst];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1819,6 +1819,41 @@
 	return res > a;
 }
 
+static bool check_reg_sane_offset(struct bpf_verifier_env *env,
+				  const struct bpf_reg_state *reg,
+				  enum bpf_reg_type type)
+{
+	bool known = tnum_is_const(reg->var_off);
+	s64 val = reg->var_off.value;
+	s64 smin = reg->smin_value;
+
+	if (known && (val >= BPF_MAX_VAR_OFF || val <= -BPF_MAX_VAR_OFF)) {
+		verbose(env, "math between %s pointer and %lld is not allowed\n",
+			reg_type_str[type], val);
+		return false;
+	}
+
+	if (reg->off >= BPF_MAX_VAR_OFF || reg->off <= -BPF_MAX_VAR_OFF) {
+		verbose(env, "%s pointer offset %d is not allowed\n",
+			reg_type_str[type], reg->off);
+		return false;
+	}
+
+	if (smin == S64_MIN) {
+		verbose(env, "math between %s pointer and register with unbounded min value is not allowed\n",
+			reg_type_str[type]);
+		return false;
+	}
+
+	if (smin >= BPF_MAX_VAR_OFF || smin <= -BPF_MAX_VAR_OFF) {
+		verbose(env, "value %lld makes %s pointer be out of bounds\n",
+			smin, reg_type_str[type]);
+		return false;
+	}
+
+	return true;
+}
+
 /* Handles arithmetic on a pointer and a scalar: computes new min/max and var_off.
  * Caller should also handle BPF_MOV case separately.
  * If we return -EACCES, caller may want to try again treating pointer as a
@@ -1886,6 +1921,10 @@
 	 */
 	dst_reg->type = ptr_reg->type;
 	dst_reg->id = ptr_reg->id;
+
+	if (!check_reg_sane_offset(env, off_reg, ptr_reg->type) ||
+	    !check_reg_sane_offset(env, ptr_reg, ptr_reg->type))
+		return -EINVAL;
 
 	switch (opcode) {
 	case BPF_ADD:
@@ -2017,6 +2056,9 @@
 		return -EACCES;
 	}
 
+	if (!check_reg_sane_offset(env, dst_reg, ptr_reg->type))
+		return -EINVAL;
+
 	__update_reg_bounds(dst_reg);
 	__reg_deduce_bounds(dst_reg);
 	__reg_bound_offset(dst_reg);
@@ -2045,6 +2087,12 @@
 	umax_val = src_reg.umax_value;
 	src_known = tnum_is_const(src_reg.var_off);
 	dst_known = tnum_is_const(dst_reg->var_off);
+
+	if (!src_known &&
+	    opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
+		__mark_reg_unknown(dst_reg);
+		return 0;
+	}
 
 	switch (opcode) {
 	case BPF_ADD:
```
