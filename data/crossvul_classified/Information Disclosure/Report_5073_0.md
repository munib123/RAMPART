# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5073_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5073_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 186-226 of the vulnerable file.

				"storage\n");
		printk(KERN_NOTICE "rock: sig=0x%02x, size=%d, remaining=%d\n",
				sig, len, rs->len);
		return -EIO;
	}
	return 0;
}

/*
 * return length of name field; 0: not found, -1: to be ignored
 */
int get_rock_ridge_filename(struct iso_directory_record *de,
			    char *retname, struct inode *inode)
{
	struct rock_state rs;
	struct rock_ridge *rr;
	int sig;
	int retnamlen = 0;
	int truncate = 0;
	int ret = 0;

	if (!ISOFS_SB(inode->i_sb)->s_rock)
		return 0;
	*retname = 0;

	init_rock_state(&rs, inode);
	setup_rock_ridge(de, inode, &rs);
repeat:

	while (rs.len > 2) { /* There may be one byte for padding somewhere */
		rr = (struct rock_ridge *)rs.chr;
		/*
		 * Ignore rock ridge info if rr->len is out of range, but
		 * don't return -EIO because that would make the file
		 * invisible.
		 */
		if (rr->len < 3)
			goto out;	/* Something got screwed up here */
		sig = isonum_721(rs.chr);
		if (rock_check_overflow(&rs, sig))
			goto eio;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,6 +203,8 @@
 	int retnamlen = 0;
 	int truncate = 0;
 	int ret = 0;
+	char *p;
+	int len;
 
 	if (!ISOFS_SB(inode->i_sb)->s_rock)
 		return 0;
@@ -267,12 +269,17 @@
 					rr->u.NM.flags);
 				break;
 			}
-			if ((strlen(retname) + rr->len - 5) >= 254) {
+			len = rr->len - 5;
+			if (retnamlen + len >= 254) {
 				truncate = 1;
 				break;
 			}
-			strncat(retname, rr->u.NM.name, rr->len - 5);
-			retnamlen += rr->len - 5;
+			p = memchr(rr->u.NM.name, '\0', len);
+			if (unlikely(p))
+				len = p - rr->u.NM.name;
+			memcpy(retname + retnamlen, rr->u.NM.name, len);
+			retnamlen += len;
+			retname[retnamlen] = '\0';
 			break;
 		case SIG('R', 'E'):
 			kfree(rs.buffer);
```
