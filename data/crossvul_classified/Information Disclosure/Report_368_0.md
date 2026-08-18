# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 368_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `368_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 2529-2569 of the vulnerable file.

	ret = cdi->ops->get_mcn(cdi, &mcn);
	if (ret)
		return ret;

	if (copy_to_user(argp, &mcn, sizeof(mcn)))
		return -EFAULT;
	cd_dbg(CD_DO_IOCTL, "CDROM_GET_MCN successful\n");
	return 0;
}

static int cdrom_ioctl_drive_status(struct cdrom_device_info *cdi,
		unsigned long arg)
{
	cd_dbg(CD_DO_IOCTL, "entering CDROM_DRIVE_STATUS\n");

	if (!(cdi->ops->capability & CDC_DRIVE_STATUS))
		return -ENOSYS;
	if (!CDROM_CAN(CDC_SELECT_DISC) ||
	    (arg == CDSL_CURRENT || arg == CDSL_NONE))
		return cdi->ops->drive_status(cdi, CDSL_CURRENT);
	if (((int)arg >= cdi->capacity))
		return -EINVAL;
	return cdrom_slot_status(cdi, arg);
}

/*
 * Ok, this is where problems start.  The current interface for the
 * CDROM_DISC_STATUS ioctl is flawed.  It makes the false assumption that
 * CDs are all CDS_DATA_1 or all CDS_AUDIO, etc.  Unfortunately, while this
 * is often the case, it is also very common for CDs to have some tracks
 * with data, and some tracks with audio.  Just because I feel like it,
 * I declare the following to be the best way to cope.  If the CD has ANY
 * data tracks on it, it will be returned as a data CD.  If it has any XA
 * tracks, I will return it as that.  Now I could simplify this interface
 * by combining these  returns with the above, but this more clearly
 * demonstrates the problem with the current interface.  Too bad this
 * wasn't designed to use bitmasks...         -Erik
 *
 * Well, now we have the option CDS_MIXED: a mixed-type CD.
 * User level programmers might feel the ioctl is not very useful.
 *					---david
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2546,7 +2546,7 @@
 	if (!CDROM_CAN(CDC_SELECT_DISC) ||
 	    (arg == CDSL_CURRENT || arg == CDSL_NONE))
 		return cdi->ops->drive_status(cdi, CDSL_CURRENT);
-	if (((int)arg >= cdi->capacity))
+	if (arg >= cdi->capacity)
 		return -EINVAL;
 	return cdrom_slot_status(cdi, arg);
 }
```
