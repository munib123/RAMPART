# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2864_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2864_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return -ENODEV;

	/*
	 * A whole standard-format XSAVE buffer is needed:
	 */
	if ((pos != 0) || (count < fpu_user_xstate_size))
		return -EFAULT;

	xsave = &fpu->state.xsave;

	fpu__activate_fpstate_write(fpu);

	if (boot_cpu_has(X86_FEATURE_XSAVES)) {
		if (kbuf)
			ret = copy_kernel_to_xstate(xsave, kbuf);
		else
			ret = copy_user_to_xstate(xsave, ubuf);
	} else {
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, xsave, 0, -1);
	}

	/*
	 * In case of failure, mark all states as init:
	 */
	if (ret)
		fpstate_init(&fpu->state);

	/*
	 * mxcsr reserved bits must be masked to zero for security reasons.
	 */
	xsave->i387.mxcsr &= mxcsr_feature_mask;
	xsave->header.xfeatures &= xfeatures_mask;
	/*
	 * These bits must be zero.
	 */
	memset(&xsave->header.reserved, 0, 48);

	return ret;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,6 +141,10 @@
 			ret = copy_user_to_xstate(xsave, ubuf);
 	} else {
 		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, xsave, 0, -1);
+
+		/* xcomp_bv must be 0 when using uncompacted format */
+		if (!ret && xsave->header.xcomp_bv)
+			ret = -EINVAL;
 	}
 
 	/*
```
