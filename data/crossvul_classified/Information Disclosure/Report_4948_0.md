# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4948_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4948_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 2065-2105 of the vulnerable file.

	for (i = 0; i < insn_cnt; i++, insn++)
		if (insn->code == (BPF_LD | BPF_IMM | BPF_DW))
			insn->src_reg = 0;
}

static void adjust_branches(struct bpf_prog *prog, int pos, int delta)
{
	struct bpf_insn *insn = prog->insnsi;
	int insn_cnt = prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (BPF_CLASS(insn->code) != BPF_JMP ||
		    BPF_OP(insn->code) == BPF_CALL ||
		    BPF_OP(insn->code) == BPF_EXIT)
			continue;

		/* adjust offset of jmps if necessary */
		if (i < pos && i + insn->off + 1 > pos)
			insn->off += delta;
		else if (i > pos && i + insn->off + 1 < pos)
			insn->off -= delta;
	}
}

/* convert load instructions that access fields of 'struct __sk_buff'
 * into sequence of instructions that access fields of 'struct sk_buff'
 */
static int convert_ctx_accesses(struct verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	struct bpf_insn insn_buf[16];
	struct bpf_prog *new_prog;
	u32 cnt;
	int i;
	enum bpf_access_type type;

	if (!env->prog->aux->ops->convert_ctx_access)
		return 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2082,7 +2082,7 @@
 		/* adjust offset of jmps if necessary */
 		if (i < pos && i + insn->off + 1 > pos)
 			insn->off += delta;
-		else if (i > pos && i + insn->off + 1 < pos)
+		else if (i > pos + delta && i + insn->off + 1 <= pos + delta)
 			insn->off -= delta;
 	}
 }
```
