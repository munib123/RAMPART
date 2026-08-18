# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_2
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_2`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

 *
 * 11/01/01 - jbarnes - initial revision
 * 9/10/04 - Christoph Lameter - remove interrupt support for kernel inclusion
 * 10/1/04 - Christoph Lameter - provide posix clock CLOCK_SGI_CYCLE
 * 10/13/04 - Christoph Lameter, Dimitri Sivanich - provide timer interrupt
 *		support via the posix timer interface
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mmtimer.h>
#include <linux/miscdevice.h>
#include <linux/posix-timers.h>
#include <linux/interrupt.h>

#include <asm/uaccess.h>
#include <asm/sn/addrs.h>
#include <asm/sn/intr.h>
#include <asm/sn/shub_mmr.h>
#include <asm/sn/nodepda.h>
#include <asm/sn/shubio.h>

MODULE_AUTHOR("Jesse Barnes <jbarnes@sgi.com>");
MODULE_DESCRIPTION("SGI Altix RTC Timer");
MODULE_LICENSE("GPL");

/* name of the device, usually in /dev */
#define MMTIMER_NAME "mmtimer"
#define MMTIMER_DESC "SGI Altix RTC Timer"
#define MMTIMER_VERSION "2.1"

#define RTC_BITS 55 /* 55 bits for this implementation */

extern unsigned long sn_rtc_cycles_per_second;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,8 @@
 #include <linux/miscdevice.h>
 #include <linux/posix-timers.h>
 #include <linux/interrupt.h>
+#include <linux/time.h>
+#include <linux/math64.h>
 
 #include <asm/uaccess.h>
 #include <asm/sn/addrs.h>
@@ -472,8 +474,8 @@
 
 	nsec = rtc_time() * sgi_clock_period
 			+ sgi_clock_offset.tv_nsec;
-	tp->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &tp->tv_nsec)
-			+ sgi_clock_offset.tv_sec;
+	*tp = ns_to_timespec(nsec);
+	tp->tv_sec += sgi_clock_offset.tv_sec;
 	return 0;
 };
 
@@ -481,11 +483,11 @@
 {
 
 	u64 nsec;
-	u64 rem;
+	u32 rem;
 
 	nsec = rtc_time() * sgi_clock_period;
 
-	sgi_clock_offset.tv_sec = tp->tv_sec - div_long_long_rem(nsec, NSEC_PER_SEC, &rem);
+	sgi_clock_offset.tv_sec = tp->tv_sec - div_u64_rem(nsec, NSEC_PER_SEC, &rem);
 
 	if (rem <= tp->tv_nsec)
 		sgi_clock_offset.tv_nsec = tp->tv_sec - rem;
@@ -644,9 +646,6 @@
 	return 0;
 }
 
-#define timespec_to_ns(x) ((x).tv_nsec + (x).tv_sec * NSEC_PER_SEC)
-#define ns_to_timespec(ts, nsec) (ts).tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &(ts).tv_nsec)
-
 /* Assumption: it_lock is already held with irq's disabled */
 static void sgi_timer_get(struct k_itimer *timr, struct itimerspec *cur_setting)
 {
@@ -659,9 +658,8 @@
 		return;
 	}
 
-	ns_to_timespec(cur_setting->it_interval, timr->it.mmtimer.incr * sgi_clock_period);
-	ns_to_timespec(cur_setting->it_value, (timr->it.mmtimer.expires - rtc_time())* sgi_clock_period);
-	return;
+	cur_setting->it_interval = ns_to_timespec(timr->it.mmtimer.incr * sgi_clock_period);
+	cur_setting->it_value = ns_to_timespec((timr->it.mmtimer.expires - rtc_time()) * sgi_clock_period);
 }
 
 
@@ -679,8 +677,8 @@
 		sgi_timer_get(timr, old_setting);
 
 	sgi_timer_del(timr);
-	when = timespec_to_ns(new_setting->it_value);
-	period = timespec_to_ns(new_setting->it_interval);
+	when = timespec_to_ns(&new_setting->it_value);
+	period = timespec_to_ns(&new_setting->it_interval);
 
 	if (when == 0)
 		/* Clear timer */
@@ -695,7 +693,7 @@
 		unsigned long now;
 
 		getnstimeofday(&n);
-		now = timespec_to_ns(n);
+		now = timespec_to_ns(&n);
 		if (when > now)
 			when -= now;
 		else
```
