# CrossVul Fix Pair: 7PK in c
**Pair ID:** 5010_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5010_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 77-128 of the vulnerable file.

#endif
	else
		rnd = (unsigned long)get_random_int() & ((1 << mmap_rnd_bits) - 1);

	return rnd << PAGE_SHIFT;
}

static unsigned long mmap_base(unsigned long rnd)
{
	unsigned long gap = rlimit(RLIMIT_STACK);

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap - rnd);
}

/*
 * Bottom-up (legacy) layout on X86_32 did not support randomization, X86_64
 * does, but not when emulating X86_32
 */
static unsigned long mmap_legacy_base(unsigned long rnd)
{
	if (mmap_is_ia32())
		return TASK_UNMAPPED_BASE;
	else
		return TASK_UNMAPPED_BASE + rnd;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	mm->mmap_legacy_base = mmap_legacy_base(random_factor);

	if (mmap_is_legacy()) {
		mm->mmap_base = mm->mmap_legacy_base;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		mm->mmap_base = mmap_base(random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,18 +94,6 @@
 }
 
 /*
- * Bottom-up (legacy) layout on X86_32 did not support randomization, X86_64
- * does, but not when emulating X86_32
- */
-static unsigned long mmap_legacy_base(unsigned long rnd)
-{
-	if (mmap_is_ia32())
-		return TASK_UNMAPPED_BASE;
-	else
-		return TASK_UNMAPPED_BASE + rnd;
-}
-
-/*
  * This function, called very early during the creation of a new
  * process VM image, sets up which VM layout function to use:
  */
@@ -116,7 +104,7 @@
 	if (current->flags & PF_RANDOMIZE)
 		random_factor = arch_mmap_rnd();
 
-	mm->mmap_legacy_base = mmap_legacy_base(random_factor);
+	mm->mmap_legacy_base = TASK_UNMAPPED_BASE + random_factor;
 
 	if (mmap_is_legacy()) {
 		mm->mmap_base = mm->mmap_legacy_base;
```
