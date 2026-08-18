# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 39-79 of the vulnerable file.

		__res = 0;						\
	if (__h->e_ident[EI_CLASS] != ELFCLASS32)			\
		__res = 0;						\
	if ((__h->e_flags & EF_MIPS_ABI2) != 0)				\
		__res = 0;						\
	if (((__h->e_flags & EF_MIPS_ABI) != 0) &&			\
	    ((__h->e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_O32))		\
		__res = 0;						\
									\
	__res;								\
})

#define TASK32_SIZE		0x7fff8000UL
#undef ELF_ET_DYN_BASE
#define ELF_ET_DYN_BASE         (TASK32_SIZE / 3 * 2)

#include <asm/processor.h>
#include <linux/module.h>
#include <linux/elfcore.h>
#include <linux/compat.h>

#define elf_prstatus elf_prstatus32
struct elf_prstatus32
{
	struct elf_siginfo pr_info;	/* Info associated with signal */
	short	pr_cursig;		/* Current signal */
	unsigned int pr_sigpend;	/* Set of pending signals */
	unsigned int pr_sighold;	/* Set of held signals */
	pid_t	pr_pid;
	pid_t	pr_ppid;
	pid_t	pr_pgrp;
	pid_t	pr_sid;
	struct compat_timeval pr_utime;	/* User time */
	struct compat_timeval pr_stime;	/* System time */
	struct compat_timeval pr_cutime;/* Cumulative user time */
	struct compat_timeval pr_cstime;/* Cumulative system time */
	elf_gregset_t pr_reg;	/* GP registers */
	int pr_fpvalid;		/* True if math co-processor being used.  */
};

#define elf_prpsinfo elf_prpsinfo32
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
 #include <linux/module.h>
 #include <linux/elfcore.h>
 #include <linux/compat.h>
+#include <linux/math64.h>
 
 #define elf_prstatus elf_prstatus32
 struct elf_prstatus32
@@ -104,8 +105,8 @@
 	 * one divide.
 	 */
 	u64 nsec = (u64)jiffies * TICK_NSEC;
-	long rem;
-	value->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &rem);
+	u32 rem;
+	value->tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
 	value->tv_usec = rem / NSEC_PER_USEC;
 }
 
```
