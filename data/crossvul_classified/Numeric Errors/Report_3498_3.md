# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_3
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_3`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 16-73 of the vulnerable file.

 *
 * This ends up being the most efficient "calling
 * convention" on x86.
 */
#define do_div(n, base)						\
({								\
	unsigned long __upper, __low, __high, __mod, __base;	\
	__base = (base);					\
	asm("":"=a" (__low), "=d" (__high) : "A" (n));		\
	__upper = __high;					\
	if (__high) {						\
		__upper = __high % (__base);			\
		__high = __high / (__base);			\
	}							\
	asm("divl %2":"=a" (__low), "=d" (__mod)		\
	    : "rm" (__base), "0" (__low), "1" (__upper));	\
	asm("":"=A" (n) : "a" (__low), "d" (__high));		\
	__mod;							\
})

/*
 * (long)X = ((long long)divs) / (long)div
 * (long)rem = ((long long)divs) % (long)div
 *
 * Warning, this will do an exception if X overflows.
 */
#define div_long_long_rem(a, b, c) div_ll_X_l_rem(a, b, c)

static inline long div_ll_X_l_rem(long long divs, long div, long *rem)
{
	long dum2;
	asm("divl %2":"=a"(dum2), "=d"(*rem)
	    : "rm"(div), "A"(divs));

	return dum2;

}

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	union {
		u64 v64;
		u32 v32[2];
	} d = { dividend };
	u32 upper;

	upper = d.v32[1];
	d.v32[1] = 0;
	if (upper >= divisor) {
		d.v32[1] = upper / divisor;
		upper %= divisor;
	}
	asm ("divl %2" : "=a" (d.v32[0]), "=d" (*remainder) :
		"rm" (divisor), "0" (d.v32[0]), "1" (upper));
	return d.v64;
}
#define div_u64_rem	div_u64_rem

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,24 +33,6 @@
 	__mod;							\
 })
 
-/*
- * (long)X = ((long long)divs) / (long)div
- * (long)rem = ((long long)divs) % (long)div
- *
- * Warning, this will do an exception if X overflows.
- */
-#define div_long_long_rem(a, b, c) div_ll_X_l_rem(a, b, c)
-
-static inline long div_ll_X_l_rem(long long divs, long div, long *rem)
-{
-	long dum2;
-	asm("divl %2":"=a"(dum2), "=d"(*rem)
-	    : "rm"(div), "A"(divs));
-
-	return dum2;
-
-}
-
 static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
 {
 	union {
```
