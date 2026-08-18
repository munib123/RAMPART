# CrossVul Fix Pair: Improper Privilege Management in shell
**Pair ID:** 5623_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5623_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```bash
Lines 1-21 of the vulnerable file.

# source autojump on BASH or ZSH depending on the shell

shell=`echo ${SHELL} | awk -F/ '{ print $NF }'`

# prevent circular loop for sh shells
if [ "${shell}" = "sh" ]; then
	return 0

# check local install
elif [ -s ~/.autojump/etc/profile.d/autojump.${shell} ]; then
	source ~/.autojump/etc/profile.d/autojump.${shell}

# check global install
elif [ -s /etc/profile.d/autojump.${shell} ]; then
	source /etc/profile.d/autojump.${shell}

# check custom install locations (modified by Homebrew or using --destdir option)
elif [ -s custom_install/autojump.${shell} ]; then
	source custom_install/autojump.${shell}

fi
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,7 @@
 	source /etc/profile.d/autojump.${shell}
 
 # check custom install locations (modified by Homebrew or using --destdir option)
-elif [ -s custom_install/autojump.${shell} ]; then
-	source custom_install/autojump.${shell}
+elif [ -s /destdir_${RANDOM}_install/autojump.${shell} ]; then
+	source /destdir_${RANDOM}_install/autojump.${shell}
 
 fi
```
