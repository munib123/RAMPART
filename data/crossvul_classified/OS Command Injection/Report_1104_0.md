# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 1104_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1104_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 2563-2603 of the vulnerable file.

					eprintf ("Missing \" in (%s).", cmd);
					r_list_free (tmpenvs);
					return false;
				}
				*p++ = 0;
				if (!*p) {
					eos = true;
				}
			} else {
				char *sc = strchr (cmd, ';');
				if (sc) {
					*sc = 0;
				}
				r_core_cmd0 (core, cmd);
				if (!sc) {
					break;
				}
				cmd = sc + 1;
				continue;
			}
			if (*p) {
				// workaround :D
				if (p[0] == '@') {
					p--;
				}
				while (p[1] == ';' || IS_WHITESPACE (p[1])) {
					p++;
				}
				if (p[1] == '@' || (p[1] && p[2] == '@')) {
					char *q = strchr (p + 1, '"');
					if (q) {
						*q = 0;
					}
					haveQuote = q != NULL;
					oseek = core->offset;
					r_core_seek (core, r_num_math (core->num, p + 2), 1);
					if (q) {
						*p = '"';
						p = q;
					} else {
						p = strchr (p + 1, ';');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2580,6 +2580,7 @@
 				cmd = sc + 1;
 				continue;
 			}
+			char op0 = 0;
 			if (*p) {
 				// workaround :D
 				if (p[0] == '@') {
@@ -2591,6 +2592,7 @@
 				if (p[1] == '@' || (p[1] && p[2] == '@')) {
 					char *q = strchr (p + 1, '"');
 					if (q) {
+						op0 = *q;
 						*q = 0;
 					}
 					haveQuote = q != NULL;
@@ -2644,9 +2646,9 @@
 					cmd = p + 1;
 				} else {
 					if (*p == '"') {
-						cmd = p + 1;
+						cmd = p;
 					} else {
-						*p = '"';
+						*p = op0;
 						cmd = p;
 					}
 				}
```
