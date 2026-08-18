# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 4935_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4935_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 6-46 of the vulnerable file.

 * Kylene Hall <kjhall@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * File: evm_main.c
 *	implements evm_inode_setxattr, evm_inode_post_setxattr,
 *	evm_inode_removexattr, and evm_verifyxattr
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/audit.h>
#include <linux/xattr.h>
#include <linux/integrity.h>
#include <linux/evm.h>
#include <crypto/hash.h>
#include "evm.h"

int evm_initialized;

static char *integrity_status_msg[] = {
	"pass", "fail", "no_label", "no_xattrs", "unknown"
};
char *evm_hmac = "hmac(sha1)";
char *evm_hash = "sha1";
int evm_hmac_attrs;

char *evm_config_xattrnames[] = {
#ifdef CONFIG_SECURITY_SELINUX
	XATTR_NAME_SELINUX,
#endif
#ifdef CONFIG_SECURITY_SMACK
	XATTR_NAME_SMACK,
#ifdef CONFIG_EVM_EXTRA_SMACK_XATTRS
	XATTR_NAME_SMACKEXEC,
	XATTR_NAME_SMACKTRANSMUTE,
	XATTR_NAME_SMACKMMAP,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 #include <linux/integrity.h>
 #include <linux/evm.h>
 #include <crypto/hash.h>
+#include <crypto/algapi.h>
 #include "evm.h"
 
 int evm_initialized;
@@ -148,7 +149,7 @@
 				   xattr_value_len, calc.digest);
 		if (rc)
 			break;
-		rc = memcmp(xattr_data->digest, calc.digest,
+		rc = crypto_memneq(xattr_data->digest, calc.digest,
 			    sizeof(calc.digest));
 		if (rc)
 			rc = -EINVAL;
```
