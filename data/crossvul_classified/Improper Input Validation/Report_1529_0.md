# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1529_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1529_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 65-105 of the vulnerable file.

			"    jmp  2b\n"			\
			".previous\n"			\
			_ASM_EXTABLE(1b, 3b)		\
			: [err] "=r" (err)

/*
 * This function is called only during boot time when x86 caps are not set
 * up and alternative can not be used yet.
 */
static inline int xsave_state_booting(struct xsave_struct *fx, u64 mask)
{
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err = 0;

	WARN_ON(system_state != SYSTEM_BOOTING);

	if (boot_cpu_has(X86_FEATURE_XSAVES))
		asm volatile("1:"XSAVES"\n\t"
			"2:\n\t"
			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
			:   "memory");
	else
		asm volatile("1:"XSAVE"\n\t"
			"2:\n\t"
			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
			:   "memory");

	asm volatile(xstate_fault
		     : "0" (0)
		     : "memory");

	return err;
}

/*
 * This function is called only during boot time when x86 caps are not set
 * up and alternative can not be used yet.
 */
static inline int xrstor_state_booting(struct xsave_struct *fx, u64 mask)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,18 +82,15 @@
 	if (boot_cpu_has(X86_FEATURE_XSAVES))
 		asm volatile("1:"XSAVES"\n\t"
 			"2:\n\t"
-			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
+			     xstate_fault
+			: "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
 			:   "memory");
 	else
 		asm volatile("1:"XSAVE"\n\t"
 			"2:\n\t"
-			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
-			:   "memory");
-
-	asm volatile(xstate_fault
-		     : "0" (0)
-		     : "memory");
-
+			     xstate_fault
+			: "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
+			:   "memory");
 	return err;
 }
 
@@ -112,18 +109,15 @@
 	if (boot_cpu_has(X86_FEATURE_XSAVES))
 		asm volatile("1:"XRSTORS"\n\t"
 			"2:\n\t"
-			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
+			     xstate_fault
+			: "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
 			:   "memory");
 	else
 		asm volatile("1:"XRSTOR"\n\t"
 			"2:\n\t"
-			: : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
-			:   "memory");
-
-	asm volatile(xstate_fault
-		     : "0" (0)
-		     : "memory");
-
+			     xstate_fault
+			: "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
+			:   "memory");
 	return err;
 }
 
@@ -149,9 +143,9 @@
 	 */
 	alternative_input_2(
 		"1:"XSAVE,
-		"1:"XSAVEOPT,
+		XSAVEOPT,
 		X86_FEATURE_XSAVEOPT,
-		"1:"XSAVES,
+		XSAVES,
 		X86_FEATURE_XSAVES,
 		[fx] "D" (fx), "a" (lmask), "d" (hmask) :
 		"memory");
@@ -178,7 +172,7 @@
 	 */
 	alternative_input(
 		"1: " XRSTOR,
-		"1: " XRSTORS,
+		XRSTORS,
 		X86_FEATURE_XSAVES,
 		"D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
 		: "memory");
```
