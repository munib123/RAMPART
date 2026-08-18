# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1821_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1821_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 858-898 of the vulnerable file.

#endif /* CONFIG_VSX */

#ifdef CONFIG_SPE
	/* SPE regs are not checkpointed with TM, so this section is
	 * simply the same as in restore_user_regs().
	 */
	regs->msr &= ~MSR_SPE;
	if (msr & MSR_SPE) {
		if (__copy_from_user(current->thread.evr, &sr->mc_vregs,
				     ELF_NEVRREG * sizeof(u32)))
			return 1;
	} else if (current->thread.used_spe)
		memset(current->thread.evr, 0, ELF_NEVRREG * sizeof(u32));

	/* Always get SPEFSCR back */
	if (__get_user(current->thread.spefscr, (u32 __user *)&sr->mc_vregs
		       + ELF_NEVRREG))
		return 1;
#endif /* CONFIG_SPE */

	/* Now, recheckpoint.  This loads up all of the checkpointed (older)
	 * registers, including FP and V[S]Rs.  After recheckpointing, the
	 * transactional versions should be loaded.
	 */
	tm_enable();
	/* Make sure the transaction is marked as failed */
	current->thread.tm_texasr |= TEXASR_FS;
	/* This loads the checkpointed FP/VEC state, if used */
	tm_recheckpoint(&current->thread, msr);
	/* Get the top half of the MSR */
	if (__get_user(msr_hi, &tm_sr->mc_gregs[PT_MSR]))
		return 1;
	/* Pull in MSR TM from user context */
	regs->msr = (regs->msr & ~MSR_TS_MASK) | ((msr_hi<<32) & MSR_TS_MASK);

	/* This loads the speculative FP/VEC state, if used */
	if (msr & MSR_FP) {
		do_load_up_transact_fpu(&current->thread);
		regs->msr |= (MSR_FP | current->thread.fpexc_mode);
	}
#ifdef CONFIG_ALTIVEC
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -875,6 +875,15 @@
 		return 1;
 #endif /* CONFIG_SPE */
 
+	/* Get the top half of the MSR from the user context */
+	if (__get_user(msr_hi, &tm_sr->mc_gregs[PT_MSR]))
+		return 1;
+	msr_hi <<= 32;
+	/* If TM bits are set to the reserved value, it's an invalid context */
+	if (MSR_TM_RESV(msr_hi))
+		return 1;
+	/* Pull in the MSR TM bits from the user context */
+	regs->msr = (regs->msr & ~MSR_TS_MASK) | (msr_hi & MSR_TS_MASK);
 	/* Now, recheckpoint.  This loads up all of the checkpointed (older)
 	 * registers, including FP and V[S]Rs.  After recheckpointing, the
 	 * transactional versions should be loaded.
@@ -884,11 +893,6 @@
 	current->thread.tm_texasr |= TEXASR_FS;
 	/* This loads the checkpointed FP/VEC state, if used */
 	tm_recheckpoint(&current->thread, msr);
-	/* Get the top half of the MSR */
-	if (__get_user(msr_hi, &tm_sr->mc_gregs[PT_MSR]))
-		return 1;
-	/* Pull in MSR TM from user context */
-	regs->msr = (regs->msr & ~MSR_TS_MASK) | ((msr_hi<<32) & MSR_TS_MASK);
 
 	/* This loads the speculative FP/VEC state, if used */
 	if (msr & MSR_FP) {
```
