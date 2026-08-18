# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4819_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4819_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 6-46 of the vulnerable file.

   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Modified by Jeremy Allison 1995.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   Modified by Steve French (sfrench@us.ibm.com) 2002-2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <crypto/skcipher.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include "cifs_fs_sb.h"
#include "cifs_unicode.h"
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifs_debug.h"
#include "cifsproto.h"

#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,7 @@
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
 
-#include <crypto/skcipher.h>
+#include <linux/crypto.h>
 #include <linux/module.h>
 #include <linux/slab.h>
 #include <linux/fs.h>
@@ -69,46 +69,22 @@
 static int
 smbhash(unsigned char *out, const unsigned char *in, unsigned char *key)
 {
-	int rc;
 	unsigned char key2[8];
-	struct crypto_skcipher *tfm_des;
-	struct scatterlist sgin, sgout;
-	struct skcipher_request *req;
+	struct crypto_cipher *tfm_des;
 
 	str_to_key(key, key2);
 
-	tfm_des = crypto_alloc_skcipher("ecb(des)", 0, CRYPTO_ALG_ASYNC);
+	tfm_des = crypto_alloc_cipher("des", 0, 0);
 	if (IS_ERR(tfm_des)) {
-		rc = PTR_ERR(tfm_des);
 		cifs_dbg(VFS, "could not allocate des crypto API\n");
-		goto smbhash_err;
-	}
-
-	req = skcipher_request_alloc(tfm_des, GFP_KERNEL);
-	if (!req) {
-		rc = -ENOMEM;
-		cifs_dbg(VFS, "could not allocate des crypto API\n");
-		goto smbhash_free_skcipher;
-	}
-
-	crypto_skcipher_setkey(tfm_des, key2, 8);
-
-	sg_init_one(&sgin, in, 8);
-	sg_init_one(&sgout, out, 8);
-
-	skcipher_request_set_callback(req, 0, NULL, NULL);
-	skcipher_request_set_crypt(req, &sgin, &sgout, 8, NULL);
-
-	rc = crypto_skcipher_encrypt(req);
-	if (rc)
-		cifs_dbg(VFS, "could not encrypt crypt key rc: %d\n", rc);
-
-	skcipher_request_free(req);
-
-smbhash_free_skcipher:
-	crypto_free_skcipher(tfm_des);
-smbhash_err:
-	return rc;
+		return PTR_ERR(tfm_des);
+	}
+
+	crypto_cipher_setkey(tfm_des, key2, 8);
+	crypto_cipher_encrypt_one(tfm_des, out, in);
+	crypto_free_cipher(tfm_des);
+
+	return 0;
 }
 
 static int
```
