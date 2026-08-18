# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3541_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3541_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 863-903 of the vulnerable file.

#define PVR_850		PVR_821
#define PVR_860		PVR_821
#define PVR_8240	0x00810100
#define PVR_8245	0x80811014
#define PVR_8260	PVR_8240

/* 476 Simulator seems to currently have the PVR of the 602... */
#define PVR_476_ISS	0x00052000

/* 64-bit processors */
/* XXX the prefix should be PVR_, we'll do a global sweep to fix it one day */
#define PV_NORTHSTAR	0x0033
#define PV_PULSAR	0x0034
#define PV_POWER4	0x0035
#define PV_ICESTAR	0x0036
#define PV_SSTAR	0x0037
#define PV_POWER4p	0x0038
#define PV_970		0x0039
#define PV_POWER5	0x003A
#define PV_POWER5p	0x003B
#define PV_970FX	0x003C
#define PV_630		0x0040
#define PV_630p	0x0041
#define PV_970MP	0x0044
#define PV_970GX	0x0045
#define PV_BE		0x0070
#define PV_PA6T		0x0090

/* Macros for setting and retrieving special purpose registers */
#ifndef __ASSEMBLY__
#define mfmsr()		({unsigned long rval; \
			asm volatile("mfmsr %0" : "=r" (rval)); rval;})
#ifdef CONFIG_PPC_BOOK3S_64
#define __mtmsrd(v, l)	asm volatile("mtmsrd %0," __stringify(l) \
				     : : "r" (v) : "memory")
#define mtmsrd(v)	__mtmsrd((v), 0)
#define mtmsr(v)	mtmsrd(v)
#else
#define mtmsr(v)	asm volatile("mtmsr %0" : : "r" (v) : "memory")
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -880,6 +880,7 @@
 #define PV_970		0x0039
 #define PV_POWER5	0x003A
 #define PV_POWER5p	0x003B
+#define PV_POWER7	0x003F
 #define PV_970FX	0x003C
 #define PV_630		0x0040
 #define PV_630p	0x0041
```
