# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2391_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2391_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 345-385 of the vulnerable file.

			goto out;	/* Something got screwed up here */

		switch (sig) {
#ifndef CONFIG_ZISOFS		/* No flag for SF or ZF */
		case SIG('R', 'R'):
			if ((rr->u.RR.flags[0] &
			     (RR_PX | RR_TF | RR_SL | RR_CL)) == 0)
				goto out;
			break;
#endif
		case SIG('S', 'P'):
			if (check_sp(rr, inode))
				goto out;
			break;
		case SIG('C', 'E'):
			rs.cont_extent = isonum_733(rr->u.CE.extent);
			rs.cont_offset = isonum_733(rr->u.CE.offset);
			rs.cont_size = isonum_733(rr->u.CE.size);
			break;
		case SIG('E', 'R'):
			ISOFS_SB(inode->i_sb)->s_rock = 1;
			printk(KERN_DEBUG "ISO 9660 Extensions: ");
			{
				int p;
				for (p = 0; p < rr->u.ER.len_id; p++)
					printk("%c", rr->u.ER.data[p]);
			}
			printk("\n");
			break;
		case SIG('P', 'X'):
			inode->i_mode = isonum_733(rr->u.PX.mode);
			set_nlink(inode, isonum_733(rr->u.PX.n_links));
			i_uid_write(inode, isonum_733(rr->u.PX.uid));
			i_gid_write(inode, isonum_733(rr->u.PX.gid));
			break;
		case SIG('P', 'N'):
			{
				int high, low;
				high = isonum_733(rr->u.PN.dev_high);
				low = isonum_733(rr->u.PN.dev_low);
				/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -362,6 +362,9 @@
 			rs.cont_size = isonum_733(rr->u.CE.size);
 			break;
 		case SIG('E', 'R'):
+			/* Invalid length of ER tag id? */
+			if (rr->u.ER.len_id + offsetof(struct rock_ridge, u.ER.data) > rr->len)
+				goto out;
 			ISOFS_SB(inode->i_sb)->s_rock = 1;
 			printk(KERN_DEBUG "ISO 9660 Extensions: ");
 			{
```
