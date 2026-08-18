# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2864_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2864_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 307-347 of the vulnerable file.

	if (ia32_fxstate) {
		/*
		 * For 32-bit frames with fxstate, copy the user state to the
		 * thread's fpu state, reconstruct fxstate from the fsave
		 * header. Sanitize the copied state etc.
		 */
		struct fpu *fpu = &tsk->thread.fpu;
		struct user_i387_ia32_struct env;
		int err = 0;

		/*
		 * Drop the current fpu which clears fpu->fpstate_active. This ensures
		 * that any context-switch during the copy of the new state,
		 * avoids the intermediate state from getting restored/saved.
		 * Thus avoiding the new restored state from getting corrupted.
		 * We will be ready to restore/save the state only after
		 * fpu->fpstate_active is again set.
		 */
		fpu__drop(fpu);

		if (using_compacted_format())
			err = copy_user_to_xstate(&fpu->state.xsave, buf_fx);
		else
			err = __copy_from_user(&fpu->state.xsave, buf_fx, state_size);

		if (err || __copy_from_user(&env, buf, sizeof(env))) {
			fpstate_init(&fpu->state);
			trace_x86_fpu_init_state(fpu);
			err = -1;
		} else {
			sanitize_restored_xstate(tsk, &env, xfeatures, fx_only);
		}

		fpu->fpstate_active = 1;
		preempt_disable();
		fpu__restore(fpu);
		preempt_enable();

		return err;
	} else {
		/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,10 +324,15 @@
 		 */
 		fpu__drop(fpu);
 
-		if (using_compacted_format())
+		if (using_compacted_format()) {
 			err = copy_user_to_xstate(&fpu->state.xsave, buf_fx);
-		else
+		} else {
 			err = __copy_from_user(&fpu->state.xsave, buf_fx, state_size);
+
+			/* xcomp_bv must be 0 when using uncompacted format */
+			if (!err && state_size > offsetof(struct xregs_state, header) && fpu->state.xsave.header.xcomp_bv)
+				err = -EINVAL;
+		}
 
 		if (err || __copy_from_user(&env, buf, sizeof(env))) {
 			fpstate_init(&fpu->state);
```
