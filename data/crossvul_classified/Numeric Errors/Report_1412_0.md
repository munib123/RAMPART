# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1412_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1412_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 155-195 of the vulnerable file.

	(((slot < frame->allocated_stack / BPF_REG_SIZE) &&		\
	  (frame->stack[slot].slot_type[0] == STACK_SPILL))		\
	 ? &frame->stack[slot].spilled_ptr : NULL)

/* Iterate over 'frame', setting 'reg' to either NULL or a spilled register. */
#define bpf_for_each_spilled_reg(iter, frame, reg)			\
	for (iter = 0, reg = bpf_get_spilled_reg(iter, frame);		\
	     iter < frame->allocated_stack / BPF_REG_SIZE;		\
	     iter++, reg = bpf_get_spilled_reg(iter, frame))

/* linked list of verifier states used to prune search */
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
};

/* Possible states for alu_state member. */
#define BPF_ALU_SANITIZE_SRC		1U
#define BPF_ALU_SANITIZE_DST		2U
#define BPF_ALU_NEG_VALUE		(1U << 2)
#define BPF_ALU_SANITIZE		(BPF_ALU_SANITIZE_SRC | \
					 BPF_ALU_SANITIZE_DST)

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;	/* pointer type for load/store insns */
		unsigned long map_state;	/* pointer/poison value for maps */
		s32 call_imm;			/* saved imm field of call insn */
		u32 alu_limit;			/* limit for add/sub register with pointer */
	};
	int ctx_field_size; /* the ctx field size for load insn, maybe 0 */
	int sanitize_stack_off; /* stack slot to be cleared */
	bool seen; /* this insn was processed by the verifier */
	u8 alu_state; /* used in combination with alu_limit */
};

#define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */

#define BPF_VERIFIER_TMP_LOG_SIZE	1024

struct bpf_verifier_log {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,6 +172,7 @@
 #define BPF_ALU_SANITIZE_SRC		1U
 #define BPF_ALU_SANITIZE_DST		2U
 #define BPF_ALU_NEG_VALUE		(1U << 2)
+#define BPF_ALU_NON_POINTER		(1U << 3)
 #define BPF_ALU_SANITIZE		(BPF_ALU_SANITIZE_SRC | \
 					 BPF_ALU_SANITIZE_DST)
 
```
