# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2060_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2060_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1040-1080 of the vulnerable file.

		}
		if (yi.cfg.mask & YAM_TXTAIL) {
			if (yi.cfg.txtail > YAM_MAXTXTAIL)
				return -EINVAL;
			yp->txtail = yi.cfg.txtail;
		}
		if (yi.cfg.mask & YAM_PERSIST) {
			if (yi.cfg.persist > YAM_MAXPERSIST)
				return -EINVAL;
			yp->pers = yi.cfg.persist;
		}
		if (yi.cfg.mask & YAM_SLOTTIME) {
			if (yi.cfg.slottime > YAM_MAXSLOTTIME)
				return -EINVAL;
			yp->slot = yi.cfg.slottime;
			yp->slotcnt = yp->slot / 10;
		}
		break;

	case SIOCYAMGCFG:
		yi.cfg.mask = 0xffffffff;
		yi.cfg.iobase = yp->iobase;
		yi.cfg.irq = yp->irq;
		yi.cfg.bitrate = yp->bitrate;
		yi.cfg.baudrate = yp->baudrate;
		yi.cfg.mode = yp->dupmode;
		yi.cfg.txdelay = yp->txd;
		yi.cfg.holddly = yp->holdd;
		yi.cfg.txtail = yp->txtail;
		yi.cfg.persist = yp->pers;
		yi.cfg.slottime = yp->slot;
		if (copy_to_user(ifr->ifr_data, &yi, sizeof(struct yamdrv_ioctl_cfg)))
			 return -EFAULT;
		break;

	default:
		return -EINVAL;

	}

	return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1057,6 +1057,7 @@
 		break;
 
 	case SIOCYAMGCFG:
+		memset(&yi, 0, sizeof(yi));
 		yi.cfg.mask = 0xffffffff;
 		yi.cfg.iobase = yp->iobase;
 		yi.cfg.irq = yp->irq;
```
