# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2989_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2989_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3810-3850 of the vulnerable file.

			if (env->log.level > 1)
				verbose(env, "%d:", insn_idx);
			else
				verbose(env, "\nfrom %d to %d:",
					prev_insn_idx, insn_idx);
			print_verifier_state(env, state);
			do_print_state = false;
		}

		if (env->log.level) {
			verbose(env, "%d: ", insn_idx);
			print_bpf_insn(verbose, env, insn,
				       env->allow_ptr_leaks);
		}

		err = ext_analyzer_insn_hook(env, insn_idx, prev_insn_idx);
		if (err)
			return err;

		regs = cur_regs(env);
		if (class == BPF_ALU || class == BPF_ALU64) {
			err = check_alu_op(env, insn);
			if (err)
				return err;

		} else if (class == BPF_LDX) {
			enum bpf_reg_type *prev_src_type, src_reg_type;

			/* check for reserved fields is already done */

			/* check src operand */
			err = check_reg_arg(env, insn->src_reg, SRC_OP);
			if (err)
				return err;

			err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
			if (err)
				return err;

			src_reg_type = regs[insn->src_reg].type;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3827,6 +3827,7 @@
 			return err;
 
 		regs = cur_regs(env);
+		env->insn_aux_data[insn_idx].seen = true;
 		if (class == BPF_ALU || class == BPF_ALU64) {
 			err = check_alu_op(env, insn);
 			if (err)
@@ -4022,6 +4023,7 @@
 					return err;
 
 				insn_idx++;
+				env->insn_aux_data[insn_idx].seen = true;
 			} else {
 				verbose(env, "invalid BPF_LD mode\n");
 				return -EINVAL;
@@ -4204,6 +4206,7 @@
 				u32 off, u32 cnt)
 {
 	struct bpf_insn_aux_data *new_data, *old_data = env->insn_aux_data;
+	int i;
 
 	if (cnt == 1)
 		return 0;
@@ -4213,6 +4216,8 @@
 	memcpy(new_data, old_data, sizeof(struct bpf_insn_aux_data) * off);
 	memcpy(new_data + off + cnt - 1, old_data + off,
 	       sizeof(struct bpf_insn_aux_data) * (prog_len - off - cnt + 1));
+	for (i = off; i < off + cnt - 1; i++)
+		new_data[i].seen = true;
 	env->insn_aux_data = new_data;
 	vfree(old_data);
 	return 0;
@@ -4229,6 +4234,25 @@
 	if (adjust_insn_aux_data(env, new_prog->len, off, len))
 		return NULL;
 	return new_prog;
+}
+
+/* The verifier does more data flow analysis than llvm and will not explore
+ * branches that are dead at run time. Malicious programs can have dead code
+ * too. Therefore replace all dead at-run-time code with nops.
+ */
+static void sanitize_dead_code(struct bpf_verifier_env *env)
+{
+	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
+	struct bpf_insn nop = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
+	struct bpf_insn *insn = env->prog->insnsi;
+	const int insn_cnt = env->prog->len;
+	int i;
+
+	for (i = 0; i < insn_cnt; i++) {
+		if (aux_data[i].seen)
+			continue;
+		memcpy(insn + i, &nop, sizeof(nop));
+	}
 }
 
 /* convert load instructions that access fields of 'struct __sk_buff'
@@ -4558,6 +4582,9 @@
 	free_states(env);
 
 	if (ret == 0)
+		sanitize_dead_code(env);
+
+	if (ret == 0)
 		/* program is valid, convert *(u32*)(ctx + off) accesses */
 		ret = convert_ctx_accesses(env);
 
```
