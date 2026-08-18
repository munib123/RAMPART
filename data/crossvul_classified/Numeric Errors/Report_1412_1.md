# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1412_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1412_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 3086-3126 of the vulnerable file.

	case PTR_TO_STACK:
		off = ptr_reg->off + ptr_reg->var_off.value;
		if (mask_to_left)
			*ptr_limit = MAX_BPF_STACK + off;
		else
			*ptr_limit = -off;
		return 0;
	case PTR_TO_MAP_VALUE:
		if (mask_to_left) {
			*ptr_limit = ptr_reg->umax_value + ptr_reg->off;
		} else {
			off = ptr_reg->smin_value + ptr_reg->off;
			*ptr_limit = ptr_reg->map_ptr->value_size - off;
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static int sanitize_ptr_alu(struct bpf_verifier_env *env,
			    struct bpf_insn *insn,
			    const struct bpf_reg_state *ptr_reg,
			    struct bpf_reg_state *dst_reg,
			    bool off_is_neg)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_insn_aux_data *aux = cur_aux(env);
	bool ptr_is_dst_reg = ptr_reg == dst_reg;
	u8 opcode = BPF_OP(insn->code);
	u32 alu_state, alu_limit;
	struct bpf_reg_state tmp;
	bool ret;

	if (env->allow_ptr_leaks || BPF_SRC(insn->code) == BPF_K)
		return 0;

	/* We already marked aux for masking from non-speculative
	 * paths, thus we got here in the first place. We only care
	 * to explore bad access from here.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3103,6 +3103,40 @@
 	}
 }
 
+static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
+				    const struct bpf_insn *insn)
+{
+	return env->allow_ptr_leaks || BPF_SRC(insn->code) == BPF_K;
+}
+
+static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
+				       u32 alu_state, u32 alu_limit)
+{
+	/* If we arrived here from different branches with different
+	 * state or limits to sanitize, then this won't work.
+	 */
+	if (aux->alu_state &&
+	    (aux->alu_state != alu_state ||
+	     aux->alu_limit != alu_limit))
+		return -EACCES;
+
+	/* Corresponding fixup done in fixup_bpf_calls(). */
+	aux->alu_state = alu_state;
+	aux->alu_limit = alu_limit;
+	return 0;
+}
+
+static int sanitize_val_alu(struct bpf_verifier_env *env,
+			    struct bpf_insn *insn)
+{
+	struct bpf_insn_aux_data *aux = cur_aux(env);
+
+	if (can_skip_alu_sanitation(env, insn))
+		return 0;
+
+	return update_alu_sanitation_state(aux, BPF_ALU_NON_POINTER, 0);
+}
+
 static int sanitize_ptr_alu(struct bpf_verifier_env *env,
 			    struct bpf_insn *insn,
 			    const struct bpf_reg_state *ptr_reg,
@@ -3117,7 +3151,7 @@
 	struct bpf_reg_state tmp;
 	bool ret;
 
-	if (env->allow_ptr_leaks || BPF_SRC(insn->code) == BPF_K)
+	if (can_skip_alu_sanitation(env, insn))
 		return 0;
 
 	/* We already marked aux for masking from non-speculative
@@ -3133,19 +3167,8 @@
 
 	if (retrieve_ptr_limit(ptr_reg, &alu_limit, opcode, off_is_neg))
 		return 0;
-
-	/* If we arrived here from different branches with different
-	 * limits to sanitize, then this won't work.
-	 */
-	if (aux->alu_state &&
-	    (aux->alu_state != alu_state ||
-	     aux->alu_limit != alu_limit))
+	if (update_alu_sanitation_state(aux, alu_state, alu_limit))
 		return -EACCES;
-
-	/* Corresponding fixup done in fixup_bpf_calls(). */
-	aux->alu_state = alu_state;
-	aux->alu_limit = alu_limit;
-
 do_sim:
 	/* Simulate and find potential out-of-bounds access under
 	 * speculative execution from truncation as a result of
@@ -3418,6 +3441,8 @@
 	s64 smin_val, smax_val;
 	u64 umin_val, umax_val;
 	u64 insn_bitness = (BPF_CLASS(insn->code) == BPF_ALU64) ? 64 : 32;
+	u32 dst = insn->dst_reg;
+	int ret;
 
 	if (insn_bitness == 32) {
 		/* Relevant for 32-bit RSH: Information can propagate towards
@@ -3452,6 +3477,11 @@
 
 	switch (opcode) {
 	case BPF_ADD:
+		ret = sanitize_val_alu(env, insn);
+		if (ret < 0) {
+			verbose(env, "R%d tried to add from different pointers or scalars\n", dst);
+			return ret;
+		}
 		if (signed_add_overflows(dst_reg->smin_value, smin_val) ||
 		    signed_add_overflows(dst_reg->smax_value, smax_val)) {
 			dst_reg->smin_value = S64_MIN;
@@ -3471,6 +3501,11 @@
 		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
 		break;
 	case BPF_SUB:
+		ret = sanitize_val_alu(env, insn);
+		if (ret < 0) {
+			verbose(env, "R%d tried to sub from different pointers or scalars\n", dst);
+			return ret;
+		}
 		if (signed_sub_overflows(dst_reg->smin_value, smax_val) ||
 		    signed_sub_overflows(dst_reg->smax_value, smin_val)) {
 			/* Overflow possible, we know nothing */
```
