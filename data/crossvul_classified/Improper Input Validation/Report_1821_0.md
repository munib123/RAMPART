# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1821_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1821_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 91-131 of the vulnerable file.

#define MSR_BE		__MASK(MSR_BE_LG)	/* Branch Trace */
#define MSR_DE		__MASK(MSR_DE_LG)	/* Debug Exception Enable */
#define MSR_FE1		__MASK(MSR_FE1_LG)	/* Floating Exception mode 1 */
#define MSR_IP		__MASK(MSR_IP_LG)	/* Exception prefix 0x000/0xFFF */
#define MSR_IR		__MASK(MSR_IR_LG)	/* Instruction Relocate */
#define MSR_DR		__MASK(MSR_DR_LG)	/* Data Relocate */
#define MSR_PE		__MASK(MSR_PE_LG)	/* Protection Enable */
#define MSR_PX		__MASK(MSR_PX_LG)	/* Protection Exclusive Mode */
#ifndef MSR_PMM
#define MSR_PMM		__MASK(MSR_PMM_LG)	/* Performance monitor */
#endif
#define MSR_RI		__MASK(MSR_RI_LG)	/* Recoverable Exception */
#define MSR_LE		__MASK(MSR_LE_LG)	/* Little Endian */

#define MSR_TM		__MASK(MSR_TM_LG)	/* Transactional Mem Available */
#define MSR_TS_N	0			/*  Non-transactional */
#define MSR_TS_S	__MASK(MSR_TS_S_LG)	/*  Transaction Suspended */
#define MSR_TS_T	__MASK(MSR_TS_T_LG)	/*  Transaction Transactional */
#define MSR_TS_MASK	(MSR_TS_T | MSR_TS_S)   /* Transaction State bits */
#define MSR_TM_ACTIVE(x) (((x) & MSR_TS_MASK) != 0) /* Transaction active? */
#define MSR_TM_TRANSACTIONAL(x)	(((x) & MSR_TS_MASK) == MSR_TS_T)
#define MSR_TM_SUSPENDED(x)	(((x) & MSR_TS_MASK) == MSR_TS_S)

#if defined(CONFIG_PPC_BOOK3S_64)
#define MSR_64BIT	MSR_SF

/* Server variant */
#define __MSR		(MSR_ME | MSR_RI | MSR_IR | MSR_DR | MSR_ISF |MSR_HV)
#ifdef __BIG_ENDIAN__
#define MSR_		__MSR
#define MSR_IDLE	(MSR_ME | MSR_SF | MSR_HV)
#else
#define MSR_		(__MSR | MSR_LE)
#define MSR_IDLE	(MSR_ME | MSR_SF | MSR_HV | MSR_LE)
#endif
#define MSR_KERNEL	(MSR_ | MSR_64BIT)
#define MSR_USER32	(MSR_ | MSR_PR | MSR_EE)
#define MSR_USER64	(MSR_USER32 | MSR_64BIT)
#elif defined(CONFIG_PPC_BOOK3S_32) || defined(CONFIG_8xx)
/* Default MSR for kernel mode. */
#define MSR_KERNEL	(MSR_ME|MSR_RI|MSR_IR|MSR_DR)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,6 +108,7 @@
 #define MSR_TS_T	__MASK(MSR_TS_T_LG)	/*  Transaction Transactional */
 #define MSR_TS_MASK	(MSR_TS_T | MSR_TS_S)   /* Transaction State bits */
 #define MSR_TM_ACTIVE(x) (((x) & MSR_TS_MASK) != 0) /* Transaction active? */
+#define MSR_TM_RESV(x) (((x) & MSR_TS_MASK) == MSR_TS_MASK) /* Reserved */
 #define MSR_TM_TRANSACTIONAL(x)	(((x) & MSR_TS_MASK) == MSR_TS_T)
 #define MSR_TM_SUSPENDED(x)	(((x) & MSR_TS_MASK) == MSR_TS_S)
 
```
