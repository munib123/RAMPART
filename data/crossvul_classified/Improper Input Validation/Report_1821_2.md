# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1821_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1821_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 421-461 of the vulnerable file.

	int i;
#endif
	/* copy the GPRs */
	err |= __copy_from_user(regs->gpr, tm_sc->gp_regs, sizeof(regs->gpr));
	err |= __copy_from_user(&current->thread.ckpt_regs, sc->gp_regs,
				sizeof(regs->gpr));

	/*
	 * TFHAR is restored from the checkpointed 'wound-back' ucontext's NIP.
	 * TEXASR was set by the signal delivery reclaim, as was TFIAR.
	 * Users doing anything abhorrent like thread-switching w/ signals for
	 * TM-Suspended code will have to back TEXASR/TFIAR up themselves.
	 * For the case of getting a signal and simply returning from it,
	 * we don't need to re-copy them here.
	 */
	err |= __get_user(regs->nip, &tm_sc->gp_regs[PT_NIP]);
	err |= __get_user(current->thread.tm_tfhar, &sc->gp_regs[PT_NIP]);

	/* get MSR separately, transfer the LE bit if doing signal return */
	err |= __get_user(msr, &sc->gp_regs[PT_MSR]);
	/* pull in MSR TM from user context */
	regs->msr = (regs->msr & ~MSR_TS_MASK) | (msr & MSR_TS_MASK);

	/* pull in MSR LE from user context */
	regs->msr = (regs->msr & ~MSR_LE) | (msr & MSR_LE);

	/* The following non-GPR non-FPR non-VR state is also checkpointed: */
	err |= __get_user(regs->ctr, &tm_sc->gp_regs[PT_CTR]);
	err |= __get_user(regs->link, &tm_sc->gp_regs[PT_LNK]);
	err |= __get_user(regs->xer, &tm_sc->gp_regs[PT_XER]);
	err |= __get_user(regs->ccr, &tm_sc->gp_regs[PT_CCR]);
	err |= __get_user(current->thread.ckpt_regs.ctr,
			  &sc->gp_regs[PT_CTR]);
	err |= __get_user(current->thread.ckpt_regs.link,
			  &sc->gp_regs[PT_LNK]);
	err |= __get_user(current->thread.ckpt_regs.xer,
			  &sc->gp_regs[PT_XER]);
	err |= __get_user(current->thread.ckpt_regs.ccr,
			  &sc->gp_regs[PT_CCR]);

	/* These regs are not checkpointed; they can go in 'regs'. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,6 +438,10 @@
 
 	/* get MSR separately, transfer the LE bit if doing signal return */
 	err |= __get_user(msr, &sc->gp_regs[PT_MSR]);
+	/* Don't allow reserved mode. */
+	if (MSR_TM_RESV(msr))
+		return -EINVAL;
+
 	/* pull in MSR TM from user context */
 	regs->msr = (regs->msr & ~MSR_TS_MASK) | (msr & MSR_TS_MASK);
 
```
