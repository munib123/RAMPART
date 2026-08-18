# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3480_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3480_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 129-169 of the vulnerable file.

#if XTENSA_HAVE_COPROCESSORS
	/* Flush all coprocessor registers to memory. */
	coprocessor_flush_all(ti);
	ret |= __copy_to_user(&xtregs->cp0, &ti->xtregs_cp,
			      sizeof(xtregs_coprocessor_t));
#endif
	ret |= __copy_to_user(&xtregs->opt, &regs->xtregs_opt,
			      sizeof(xtregs->opt));
	ret |= __copy_to_user(&xtregs->user,&ti->xtregs_user,
			      sizeof(xtregs->user));

	return ret ? -EFAULT : 0;
}

int ptrace_setxregs(struct task_struct *child, void __user *uregs)
{
	struct thread_info *ti = task_thread_info(child);
	struct pt_regs *regs = task_pt_regs(child);
	elf_xtregs_t *xtregs = uregs;
	int ret = 0;

#if XTENSA_HAVE_COPROCESSORS
	/* Flush all coprocessors before we overwrite them. */
	coprocessor_flush_all(ti);
	coprocessor_release_all(ti);

	ret |= __copy_from_user(&ti->xtregs_cp, &xtregs->cp0, 
				sizeof(xtregs_coprocessor_t));
#endif
	ret |= __copy_from_user(&regs->xtregs_opt, &xtregs->opt,
				sizeof(xtregs->opt));
	ret |= __copy_from_user(&ti->xtregs_user, &xtregs->user,
				sizeof(xtregs->user));

	return ret ? -EFAULT : 0;
}

int ptrace_peekusr(struct task_struct *child, long regno, long __user *ret)
{
	struct pt_regs *regs;
	unsigned long tmp;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,6 +147,9 @@
 	elf_xtregs_t *xtregs = uregs;
 	int ret = 0;
 
+	if (!access_ok(VERIFY_READ, uregs, sizeof(elf_xtregs_t)))
+		return -EFAULT;
+
 #if XTENSA_HAVE_COPROCESSORS
 	/* Flush all coprocessors before we overwrite them. */
 	coprocessor_flush_all(ti);
```
