# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5271_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5271_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2913-2953 of the vulnerable file.

	{ X86_IN16rr, X86_REG_AX, X86_REG_DX, CS_AC_WRITE, CS_AC_READ },
	{ X86_IN32rr, X86_REG_EAX, X86_REG_DX, CS_AC_WRITE, CS_AC_READ },

	{ X86_OUT8rr, X86_REG_DX, X86_REG_AL, CS_AC_READ, CS_AC_READ },
	{ X86_OUT16rr, X86_REG_DX, X86_REG_AX, CS_AC_READ, CS_AC_READ },
	{ X86_OUT32rr, X86_REG_DX, X86_REG_EAX, CS_AC_READ, CS_AC_READ },

	{ X86_INVLPGA32, X86_REG_EAX, X86_REG_ECX, CS_AC_READ, CS_AC_READ },
	{ X86_INVLPGA64, X86_REG_RAX, X86_REG_ECX, CS_AC_READ, CS_AC_READ },
};

static struct insn_reg insn_regs_intel_sorted [ARR_SIZE(insn_regs_intel)];

static int regs_cmp(const void *a, const void *b)
{
	uint16_t l = ((struct insn_reg *)a)->insn;
	uint16_t r = ((struct insn_reg *)b)->insn;
	return (l - r);
}

static bool intel_regs_sorted = false;
// return register of given instruction id
// return 0 if not found
// this is to handle instructions embedding accumulate registers into AsmStrs[]
x86_reg X86_insn_reg_intel(unsigned int id, enum cs_ac_type *access)
{
	unsigned int first = 0;
	unsigned int last = ARR_SIZE(insn_regs_intel) - 1;
	unsigned int mid = ARR_SIZE(insn_regs_intel) / 2;

	if (!intel_regs_sorted) {
		memcpy(insn_regs_intel_sorted, insn_regs_intel,
				sizeof(insn_regs_intel_sorted));
		qsort(insn_regs_intel_sorted,
				ARR_SIZE(insn_regs_intel_sorted),
				sizeof(struct insn_reg), regs_cmp);
		intel_regs_sorted = true;
	}

	while (first <= last) {
		if (insn_regs_intel_sorted[mid].insn < id) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2930,15 +2930,15 @@
 	return (l - r);
 }
 
-static bool intel_regs_sorted = false;
 // return register of given instruction id
 // return 0 if not found
 // this is to handle instructions embedding accumulate registers into AsmStrs[]
 x86_reg X86_insn_reg_intel(unsigned int id, enum cs_ac_type *access)
 {
+	static bool intel_regs_sorted = false;
 	unsigned int first = 0;
 	unsigned int last = ARR_SIZE(insn_regs_intel) - 1;
-	unsigned int mid = ARR_SIZE(insn_regs_intel) / 2;
+	unsigned int mid;
 
 	if (!intel_regs_sorted) {
 		memcpy(insn_regs_intel_sorted, insn_regs_intel,
@@ -2949,7 +2949,13 @@
 		intel_regs_sorted = true;
 	}
 
+	if (insn_regs_intel_sorted[0].insn > id ||
+			insn_regs_intel_sorted[last].insn < id) {
+		return 0;
+	}
+
 	while (first <= last) {
+		mid = (first + last) / 2;
 		if (insn_regs_intel_sorted[mid].insn < id) {
 			first = mid + 1;
 		} else if (insn_regs_intel_sorted[mid].insn == id) {
@@ -2962,7 +2968,6 @@
 				break;
 			last = mid - 1;
 		}
-		mid = (first + last) / 2;
 	}
 
 	// not found
```
