# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_7
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_7`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 375-415 of the vulnerable file.

		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}
EXPORT_SYMBOL(set_normalized_timespec);

/**
 * ns_to_timespec - Convert nanoseconds to timespec
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timespec representation of the nsec parameter.
 */
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_long_long_rem_signed(nsec, NSEC_PER_SEC, &ts.tv_nsec);
	if (unlikely(nsec < 0))
		set_normalized_timespec(&ts, ts.tv_sec, ts.tv_nsec);

	return ts;
}
EXPORT_SYMBOL(ns_to_timespec);

/**
 * ns_to_timeval - Convert nanoseconds to timeval
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timeval representation of the nsec parameter.
 */
struct timeval ns_to_timeval(const s64 nsec)
{
	struct timespec ts = ns_to_timespec(nsec);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -392,13 +392,17 @@
 struct timespec ns_to_timespec(const s64 nsec)
 {
 	struct timespec ts;
+	s32 rem;
 
 	if (!nsec)
 		return (struct timespec) {0, 0};
 
-	ts.tv_sec = div_long_long_rem_signed(nsec, NSEC_PER_SEC, &ts.tv_nsec);
-	if (unlikely(nsec < 0))
-		set_normalized_timespec(&ts, ts.tv_sec, ts.tv_nsec);
+	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
+	if (unlikely(rem < 0)) {
+		ts.tv_sec--;
+		rem += NSEC_PER_SEC;
+	}
+	ts.tv_nsec = rem;
 
 	return ts;
 }
@@ -528,8 +532,10 @@
 	 * Convert jiffies to nanoseconds and separate with
 	 * one divide.
 	 */
-	u64 nsec = (u64)jiffies * TICK_NSEC;
-	value->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &value->tv_nsec);
+	u32 rem;
+	value->tv_sec = div_u64_rem((u64)jiffies * TICK_NSEC,
+				    NSEC_PER_SEC, &rem);
+	value->tv_nsec = rem;
 }
 EXPORT_SYMBOL(jiffies_to_timespec);
 
@@ -567,12 +573,11 @@
 	 * Convert jiffies to nanoseconds and separate with
 	 * one divide.
 	 */
-	u64 nsec = (u64)jiffies * TICK_NSEC;
-	long tv_usec;
-
-	value->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &tv_usec);
-	tv_usec /= NSEC_PER_USEC;
-	value->tv_usec = tv_usec;
+	u32 rem;
+
+	value->tv_sec = div_u64_rem((u64)jiffies * TICK_NSEC,
+				    NSEC_PER_SEC, &rem);
+	value->tv_usec = rem / NSEC_PER_USEC;
 }
 EXPORT_SYMBOL(jiffies_to_timeval);
 
```
