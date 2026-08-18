# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4849_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4849_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 96-136 of the vulnerable file.


/* Compute the minimum of two values. */
#define	JAS_MIN(x, y) \
	(((x) < (y)) ? (x) : (y))

/* Compute the maximum of two values. */
#define	JAS_MAX(x, y) \
	(((x) > (y)) ? (x) : (y))

/* Compute the remainder from division (where division is defined such
  that the remainder is always nonnegative). */
#define	JAS_MOD(x, y) \
	(((x) < 0) ? (((-x) % (y)) ? ((y) - ((-(x)) % (y))) : (0)) : ((x) % (y)))

/* Compute the integer with the specified number of least significant bits
  set to one. */
#define	JAS_ONES(n) \
  ((1 << (n)) - 1)

/******************************************************************************\
* Safe integer arithmetic (i.e., with overflow checking).
\******************************************************************************/

/* Compute the product of two size_t integers with overflow checking. */
inline static bool jas_safe_size_mul(size_t x, size_t y, size_t *result)
{
	/* Check if overflow would occur */
	if (x && y > SIZE_MAX / x) {
		/* Overflow would occur. */
		*result = 0;
		return false;
	}
	*result = x * y;
	return true;
}

inline static bool jas_safe_size_add(size_t x, size_t y, size_t *result)
{
	if (y > SIZE_MAX - x) {
		*result = 0;
		return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,6 +113,24 @@
   ((1 << (n)) - 1)
 
 /******************************************************************************\
+*
+\******************************************************************************/
+
+__attribute__((no_sanitize("undefined")))
+inline static jas_int_asr(int x, int n)
+{
+	assert(n >= 0);
+	return x >> n;
+}
+
+__attribute__((no_sanitize("undefined")))
+inline static jas_int_asl(int x, int n)
+{
+	assert(n >= 0);
+	return x << n;
+}
+
+/******************************************************************************\
 * Safe integer arithmetic (i.e., with overflow checking).
 \******************************************************************************/
 
```
