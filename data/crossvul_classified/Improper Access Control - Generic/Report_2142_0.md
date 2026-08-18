# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2142_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2142_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 317-357 of the vulnerable file.


/*
 * Write a word to the user area of a process at location addr. This
 * operation does have an additional problem compared to peek_user.
 * Stores to the program status word and on the floating point
 * control register needs to get checked for validity.
 */
static int __poke_user(struct task_struct *child, addr_t addr, addr_t data)
{
	struct user *dummy = NULL;
	addr_t offset;

	if (addr < (addr_t) &dummy->regs.acrs) {
		/*
		 * psw and gprs are stored on the stack
		 */
		if (addr == (addr_t) &dummy->regs.psw.mask) {
			unsigned long mask = PSW_MASK_USER;

			mask |= is_ri_task(child) ? PSW_MASK_RI : 0;
			if ((data & ~mask) != PSW_USER_BITS)
				return -EINVAL;
			if ((data & PSW_MASK_EA) && !(data & PSW_MASK_BA))
				return -EINVAL;
		}
		*(addr_t *)((addr_t) &task_pt_regs(child)->psw + addr) = data;

	} else if (addr < (addr_t) (&dummy->regs.orig_gpr2)) {
		/*
		 * access registers are stored in the thread structure
		 */
		offset = addr - (addr_t) &dummy->regs.acrs;
#ifdef CONFIG_64BIT
		/*
		 * Very special case: old & broken 64 bit gdb writing
		 * to acrs[15] with a 64 bit value. Ignore the lower
		 * half of the value and write the upper 32 bit to
		 * acrs[15]. Sick...
		 */
		if (addr == (addr_t) &dummy->regs.acrs[15])
			child->thread.acrs[15] = (unsigned int) (data >> 32);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -334,9 +334,14 @@
 			unsigned long mask = PSW_MASK_USER;
 
 			mask |= is_ri_task(child) ? PSW_MASK_RI : 0;
-			if ((data & ~mask) != PSW_USER_BITS)
+			if ((data ^ PSW_USER_BITS) & ~mask)
+				/* Invalid psw mask. */
+				return -EINVAL;
+			if ((data & PSW_MASK_ASC) == PSW_ASC_HOME)
+				/* Invalid address-space-control bits */
 				return -EINVAL;
 			if ((data & PSW_MASK_EA) && !(data & PSW_MASK_BA))
+				/* Invalid addressing mode bits */
 				return -EINVAL;
 		}
 		*(addr_t *)((addr_t) &task_pt_regs(child)->psw + addr) = data;
@@ -672,8 +677,11 @@
 
 			mask |= is_ri_task(child) ? PSW32_MASK_RI : 0;
 			/* Build a 64 bit psw mask from 31 bit mask. */
-			if ((tmp & ~mask) != PSW32_USER_BITS)
+			if ((tmp ^ PSW32_USER_BITS) & ~mask)
 				/* Invalid psw mask. */
+				return -EINVAL;
+			if ((data & PSW32_MASK_ASC) == PSW32_ASC_HOME)
+				/* Invalid address-space-control bits */
 				return -EINVAL;
 			regs->psw.mask = (regs->psw.mask & ~PSW_MASK_USER) |
 				(regs->psw.mask & PSW_MASK_BA) |
```
