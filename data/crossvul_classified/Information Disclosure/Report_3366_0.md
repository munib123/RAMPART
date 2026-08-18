# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3366_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3366_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 281-321 of the vulnerable file.

static const char *const bpf_ldst_string[] = {
	[BPF_W >> 3]  = "u32",
	[BPF_H >> 3]  = "u16",
	[BPF_B >> 3]  = "u8",
	[BPF_DW >> 3] = "u64",
};

static const char *const bpf_jmp_string[16] = {
	[BPF_JA >> 4]   = "jmp",
	[BPF_JEQ >> 4]  = "==",
	[BPF_JGT >> 4]  = ">",
	[BPF_JGE >> 4]  = ">=",
	[BPF_JSET >> 4] = "&",
	[BPF_JNE >> 4]  = "!=",
	[BPF_JSGT >> 4] = "s>",
	[BPF_JSGE >> 4] = "s>=",
	[BPF_CALL >> 4] = "call",
	[BPF_EXIT >> 4] = "exit",
};

static void print_bpf_insn(struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		if (BPF_SRC(insn->code) == BPF_X)
			verbose("(%02x) %sr%d %s %sr%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->src_reg);
		else
			verbose("(%02x) %sr%d %s %s%d\n",
				insn->code, class == BPF_ALU ? "(u32) " : "",
				insn->dst_reg,
				bpf_alu_string[BPF_OP(insn->code) >> 4],
				class == BPF_ALU ? "(u32) " : "",
				insn->imm);
	} else if (class == BPF_STX) {
		if (BPF_MODE(insn->code) == BPF_MEM)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -298,7 +298,8 @@
 	[BPF_EXIT >> 4] = "exit",
 };
 
-static void print_bpf_insn(struct bpf_insn *insn)
+static void print_bpf_insn(const struct bpf_verifier_env *env,
+			   const struct bpf_insn *insn)
 {
 	u8 class = BPF_CLASS(insn->code);
 
@@ -362,9 +363,19 @@
 				insn->code,
 				bpf_ldst_string[BPF_SIZE(insn->code) >> 3],
 				insn->src_reg, insn->imm);
-		} else if (BPF_MODE(insn->code) == BPF_IMM) {
-			verbose("(%02x) r%d = 0x%x\n",
-				insn->code, insn->dst_reg, insn->imm);
+		} else if (BPF_MODE(insn->code) == BPF_IMM &&
+			   BPF_SIZE(insn->code) == BPF_DW) {
+			/* At this point, we already made sure that the second
+			 * part of the ldimm64 insn is accessible.
+			 */
+			u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
+			bool map_ptr = insn->src_reg == BPF_PSEUDO_MAP_FD;
+
+			if (map_ptr && !env->allow_ptr_leaks)
+				imm = 0;
+
+			verbose("(%02x) r%d = 0x%llx\n", insn->code,
+				insn->dst_reg, (unsigned long long)imm);
 		} else {
 			verbose("BUG_ld_%02x\n", insn->code);
 			return;
@@ -2853,7 +2864,7 @@
 
 		if (log_level) {
 			verbose("%d: ", insn_idx);
-			print_bpf_insn(insn);
+			print_bpf_insn(env, insn);
 		}
 
 		err = ext_analyzer_insn_hook(env, insn_idx, prev_insn_idx);
```
