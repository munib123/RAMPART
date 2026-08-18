# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 61_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `61_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1706-1746 of the vulnerable file.

				type = ARCHIVE_ENTRY_ACL_TYPE_DEFAULT;
				if (len > 7)
					field[0].start += 7;
				else
					n = 1;
			} else
				type = want_type;

			/* Check for a numeric ID in field n+1 or n+3. */
			isint(field[n + 1].start, field[n + 1].end, &id);
			/* Field n+3 is optional. */
			if (id == -1 && fields > (n + 3))
				isint(field[n + 3].start, field[n + 3].end,
				    &id);

			tag = 0;
			s = field[n].start;
			st = field[n].start + 1;
			len = field[n].end - field[n].start;

			switch (*s) {
			case 'u':
				if (len == 1 || (len == 4
				    && memcmp(st, "ser", 3) == 0))
					tag = ARCHIVE_ENTRY_ACL_USER_OBJ;
				break;
			case 'g':
				if (len == 1 || (len == 5
				    && memcmp(st, "roup", 4) == 0))
					tag = ARCHIVE_ENTRY_ACL_GROUP_OBJ;
				break;
			case 'o':
				if (len == 1 || (len == 5
				    && memcmp(st, "ther", 4) == 0))
					tag = ARCHIVE_ENTRY_ACL_OTHER;
				break;
			case 'm':
				if (len == 1 || (len == 4
				    && memcmp(st, "ask", 3) == 0))
					tag = ARCHIVE_ENTRY_ACL_MASK;
				break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1723,6 +1723,11 @@
 			st = field[n].start + 1;
 			len = field[n].end - field[n].start;
 
+			if (len == 0) {
+				ret = ARCHIVE_WARN;
+				continue;
+			}
+
 			switch (*s) {
 			case 'u':
 				if (len == 1 || (len == 4
```
