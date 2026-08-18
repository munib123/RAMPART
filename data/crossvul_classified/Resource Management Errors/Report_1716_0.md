# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1716_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1716_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 226-266 of the vulnerable file.

		return 0;
	return pinfo == (unsigned long) &sf->info &&
		puc == (unsigned long) &sf->uc;
}

static void perf_callchain_user_64(struct perf_callchain_entry *entry,
				   struct pt_regs *regs)
{
	unsigned long sp, next_sp;
	unsigned long next_ip;
	unsigned long lr;
	long level = 0;
	struct signal_frame_64 __user *sigframe;
	unsigned long __user *fp, *uregs;

	next_ip = perf_instruction_pointer(regs);
	lr = regs->link;
	sp = regs->gpr[1];
	perf_callchain_store(entry, next_ip);

	for (;;) {
		fp = (unsigned long __user *) sp;
		if (!valid_user_sp(sp, 1) || read_user_stack_64(fp, &next_sp))
			return;
		if (level > 0 && read_user_stack_64(&fp[2], &next_ip))
			return;

		/*
		 * Note: the next_sp - sp >= signal frame size check
		 * is true when next_sp < sp, which can happen when
		 * transitioning from an alternate signal stack to the
		 * normal stack.
		 */
		if (next_sp - sp >= sizeof(struct signal_frame_64) &&
		    (is_sigreturn_64_address(next_ip, sp) ||
		     (level <= 1 && is_sigreturn_64_address(lr, sp))) &&
		    sane_signal_64_frame(sp)) {
			/*
			 * This looks like an signal frame
			 */
			sigframe = (struct signal_frame_64 __user *) sp;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,7 +243,7 @@
 	sp = regs->gpr[1];
 	perf_callchain_store(entry, next_ip);
 
-	for (;;) {
+	while (entry->nr < PERF_MAX_STACK_DEPTH) {
 		fp = (unsigned long __user *) sp;
 		if (!valid_user_sp(sp, 1) || read_user_stack_64(fp, &next_sp))
 			return;
```
