# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 432_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `432_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 2428-2468 of the vulnerable file.


static int cdrom_ioctl_select_speed(struct cdrom_device_info *cdi,
		unsigned long arg)
{
	cd_dbg(CD_DO_IOCTL, "entering CDROM_SELECT_SPEED\n");

	if (!CDROM_CAN(CDC_SELECT_SPEED))
		return -ENOSYS;
	return cdi->ops->select_speed(cdi, arg);
}

static int cdrom_ioctl_select_disc(struct cdrom_device_info *cdi,
		unsigned long arg)
{
	cd_dbg(CD_DO_IOCTL, "entering CDROM_SELECT_DISC\n");

	if (!CDROM_CAN(CDC_SELECT_DISC))
		return -ENOSYS;

	if (arg != CDSL_CURRENT && arg != CDSL_NONE) {
		if ((int)arg >= cdi->capacity)
			return -EINVAL;
	}

	/*
	 * ->select_disc is a hook to allow a driver-specific way of
	 * seleting disc.  However, since there is no equivalent hook for
	 * cdrom_slot_status this may not actually be useful...
	 */
	if (cdi->ops->select_disc)
		return cdi->ops->select_disc(cdi, arg);

	cd_dbg(CD_CHANGER, "Using generic cdrom_select_disc()\n");
	return cdrom_select_disc(cdi, arg);
}

static int cdrom_ioctl_reset(struct cdrom_device_info *cdi,
		struct block_device *bdev)
{
	cd_dbg(CD_DO_IOCTL, "entering CDROM_RESET\n");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2445,7 +2445,7 @@
 		return -ENOSYS;
 
 	if (arg != CDSL_CURRENT && arg != CDSL_NONE) {
-		if ((int)arg >= cdi->capacity)
+		if (arg >= cdi->capacity)
 			return -EINVAL;
 	}
 
```
