# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2483_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2483_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-37 of the vulnerable file.


#include <asm/cache.h>

#include "entry.h"

#ifdef CONFIG_VIRT_CPU_ACCOUNTING
/* read ar.itc in advance, and use it before leaving bank 0 */
#define ACCOUNT_GET_STAMP				\
(pUStk) mov.m r20=ar.itc;
#define ACCOUNT_SYS_ENTER				\
(pUStk) br.call.spnt rp=account_sys_enter		\
	;;
#else
#define ACCOUNT_GET_STAMP
#define ACCOUNT_SYS_ENTER
#endif

/*
 * DO_SAVE_MIN switches to the kernel stacks (if necessary) and saves
 * the minimum state necessary that allows us to turn psr.ic back
 * on.
 *
 * Assumed state upon entry:
 *	psr.ic: off
 *	r31:	contains saved predicates (pr)
 *
 * Upon exit, the state is as follows:
 *	psr.ic: off
 *	 r2 = points to &pt_regs.r16
 *	 r8 = contents of ar.ccv
 *	 r9 = contents of ar.csd
 *	r10 = contents of ar.ssd
 *	r11 = FPSR_DEFAULT
 *	r12 = kernel sp (kernel virtual address)
 *	r13 = points to current task_struct (kernel virtual address)
 *	p15 = TRUE if psr.i is set in cr.ipsr
 *	predicate registers (other than p2, p3, and p15), b6, r3, r14, r15:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,9 @@
 #define ACCOUNT_GET_STAMP
 #define ACCOUNT_SYS_ENTER
 #endif
+
+.section ".data.patch.rse", "a"
+.previous
 
 /*
  * DO_SAVE_MIN switches to the kernel stacks (if necessary) and saves
@@ -40,7 +43,7 @@
  * Note that psr.ic is NOT turned on by this macro.  This is so that
  * we can pass interruption state as arguments to a handler.
  */
-#define DO_SAVE_MIN(COVER,SAVE_IFS,EXTRA)							\
+#define DO_SAVE_MIN(COVER,SAVE_IFS,EXTRA,WORKAROUND)						\
 	mov r16=IA64_KR(CURRENT);	/* M */							\
 	mov r27=ar.rsc;			/* M */							\
 	mov r20=r1;			/* A */							\
@@ -87,6 +90,7 @@
 	tbit.nz p15,p0=r29,IA64_PSR_I_BIT;							\
 	mov r29=b0										\
 	;;											\
+	WORKAROUND;										\
 	adds r16=PT(R8),r1;	/* initialize first base pointer */				\
 	adds r17=PT(R9),r1;	/* initialize second base pointer */				\
 (pKStk)	mov r18=r0;		/* make sure r18 isn't NaT */					\
@@ -206,6 +210,40 @@
 	st8 [r25]=r10;      	/* ar.ssd */	\
 	;;
 
-#define SAVE_MIN_WITH_COVER	DO_SAVE_MIN(cover, mov r30=cr.ifs,)
-#define SAVE_MIN_WITH_COVER_R19	DO_SAVE_MIN(cover, mov r30=cr.ifs, mov r15=r19)
-#define SAVE_MIN		DO_SAVE_MIN(     , mov r30=r0, )
+#define RSE_WORKAROUND				\
+(pUStk) extr.u r17=r18,3,6;			\
+(pUStk)	sub r16=r18,r22;			\
+[1:](pKStk)	br.cond.sptk.many 1f;		\
+	.xdata4 ".data.patch.rse",1b-.		\
+	;;					\
+	cmp.ge p6,p7 = 33,r17;			\
+	;;					\
+(p6)	mov r17=0x310;				\
+(p7)	mov r17=0x308;				\
+	;;					\
+	cmp.leu p1,p0=r16,r17;			\
+(p1)	br.cond.sptk.many 1f;			\
+	dep.z r17=r26,0,62;			\
+	movl r16=2f;				\
+	;;					\
+	mov ar.pfs=r17;				\
+	dep r27=r0,r27,16,14;			\
+	mov b0=r16;				\
+	;;					\
+	br.ret.sptk b0;				\
+	;;					\
+2:						\
+	mov ar.rsc=r0				\
+	;;					\
+	flushrs;				\
+	;;					\
+	mov ar.bspstore=r22			\
+	;;					\
+	mov r18=ar.bsp;				\
+	;;					\
+1:						\
+	.pred.rel "mutex", pKStk, pUStk
+
+#define SAVE_MIN_WITH_COVER	DO_SAVE_MIN(cover, mov r30=cr.ifs, , RSE_WORKAROUND)
+#define SAVE_MIN_WITH_COVER_R19	DO_SAVE_MIN(cover, mov r30=cr.ifs, mov r15=r19, RSE_WORKAROUND)
+#define SAVE_MIN			DO_SAVE_MIN(     , mov r30=r0, , )
```
