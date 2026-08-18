# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3498_8
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3498_8`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 217-257 of the vulnerable file.

		next.tv_nsec -= NSEC_PER_SEC;
	}
	mod_timer(&sync_cmos_timer, jiffies + timespec_to_jiffies(&next));
}

static void notify_cmos_timer(void)
{
	if (!no_sync_cmos_clock)
		mod_timer(&sync_cmos_timer, jiffies + 1);
}

#else
static inline void notify_cmos_timer(void) { }
#endif

/* adjtimex mainly allows reading (and writing, if superuser) of
 * kernel time-keeping variables. used by xntpd.
 */
int do_adjtimex(struct timex *txc)
{
	long mtemp, save_adjust, rem;
	s64 freq_adj;
	int result;

	/* In order to modify anything, you gotta be super-user! */
	if (txc->modes && !capable(CAP_SYS_TIME))
		return -EPERM;

	/* Now we validate the data before disabling interrupts */

	if ((txc->modes & ADJ_OFFSET_SINGLESHOT) == ADJ_OFFSET_SINGLESHOT) {
	  /* singleshot must not be used with any other mode bits */
		if (txc->modes != ADJ_OFFSET_SINGLESHOT &&
					txc->modes != ADJ_OFFSET_SS_READ)
			return -EINVAL;
	}

	if (txc->modes != ADJ_OFFSET_SINGLESHOT && (txc->modes & ADJ_OFFSET))
	  /* adjustment Offset limited to +- .512 seconds */
		if (txc->offset <= - MAXPHASE || txc->offset >= MAXPHASE )
			return -EINVAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,7 +234,7 @@
  */
 int do_adjtimex(struct timex *txc)
 {
-	long mtemp, save_adjust, rem;
+	long mtemp, save_adjust;
 	s64 freq_adj;
 	int result;
 
@@ -345,9 +345,7 @@
 		    freq_adj += time_freq;
 		    freq_adj = min(freq_adj, (s64)MAXFREQ_NSEC);
 		    time_freq = max(freq_adj, (s64)-MAXFREQ_NSEC);
-		    time_offset = div_long_long_rem_signed(time_offset,
-							   NTP_INTERVAL_FREQ,
-							   &rem);
+		    time_offset = div_s64(time_offset, NTP_INTERVAL_FREQ);
 		    time_offset <<= SHIFT_UPDATE;
 		} /* STA_PLL */
 	    } /* txc->modes & ADJ_OFFSET */
```
