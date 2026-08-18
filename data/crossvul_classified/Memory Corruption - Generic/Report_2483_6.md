# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2483_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2483_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 59-99 of the vulnerable file.


#ifdef __KERNEL__
#ifndef ASM_OFFSETS_C
#include <asm/asm-offsets.h>
#endif

/*
 * Base-2 logarithm of number of pages to allocate per task structure
 * (including register backing store and memory stack):
 */
#if defined(CONFIG_IA64_PAGE_SIZE_4KB)
# define KERNEL_STACK_SIZE_ORDER		3
#elif defined(CONFIG_IA64_PAGE_SIZE_8KB)
# define KERNEL_STACK_SIZE_ORDER		2
#elif defined(CONFIG_IA64_PAGE_SIZE_16KB)
# define KERNEL_STACK_SIZE_ORDER		1
#else
# define KERNEL_STACK_SIZE_ORDER		0
#endif

#define IA64_RBS_OFFSET			((IA64_TASK_SIZE + IA64_THREAD_INFO_SIZE + 15) & ~15)
#define IA64_STK_OFFSET			((1 << KERNEL_STACK_SIZE_ORDER)*PAGE_SIZE)

#define KERNEL_STACK_SIZE		IA64_STK_OFFSET

#endif /* __KERNEL__ */

#ifndef __ASSEMBLY__

/*
 * This struct defines the way the registers are saved on system
 * calls.
 *
 * We don't save all floating point register because the kernel
 * is compiled to use only a very small subset, so the other are
 * untouched.
 *
 * THIS STRUCTURE MUST BE A MULTIPLE 16-BYTE IN SIZE
 * (because the memory stack pointer MUST ALWAYS be aligned this way)
 *
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,7 @@
 # define KERNEL_STACK_SIZE_ORDER		0
 #endif
 
-#define IA64_RBS_OFFSET			((IA64_TASK_SIZE + IA64_THREAD_INFO_SIZE + 15) & ~15)
+#define IA64_RBS_OFFSET			((IA64_TASK_SIZE + IA64_THREAD_INFO_SIZE + 31) & ~31)
 #define IA64_STK_OFFSET			((1 << KERNEL_STACK_SIZE_ORDER)*PAGE_SIZE)
 
 #define KERNEL_STACK_SIZE		IA64_STK_OFFSET
```
