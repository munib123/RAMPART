# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 730_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `730_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/tee_ta_manager.h>
#include <mm/tee_mmu.h>
#include <string_ext.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <tee_api_defines_extensions.h>
#if defined(CFG_CRYPTO_HKDF)
#include <tee/tee_cryp_hkdf.h>
#endif
#if defined(CFG_CRYPTO_CONCAT_KDF)
#include <tee/tee_cryp_concat_kdf.h>
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
  */
 
 #include <assert.h>
+#include <compiler.h>
 #include <crypto/crypto.h>
 #include <kernel/tee_ta_manager.h>
 #include <mm/tee_mmu.h>
@@ -1547,9 +1548,15 @@
 	if (!type_props)
 		return TEE_ERROR_NOT_IMPLEMENTED;
 
-	attrs = malloc(sizeof(TEE_Attribute) * attr_count);
+	size_t alloc_size = 0;
+
+	if (MUL_OVERFLOW(sizeof(TEE_Attribute), attr_count, &alloc_size))
+		return TEE_ERROR_OVERFLOW;
+
+	attrs = malloc(alloc_size);
 	if (!attrs)
 		return TEE_ERROR_OUT_OF_MEMORY;
+
 	res = copy_in_attrs(to_user_ta_ctx(sess->ctx), usr_attrs, attr_count,
 			    attrs);
 	if (res != TEE_SUCCESS)
```
