# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5217_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5217_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-34 of the vulnerable file.

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_FLUSH
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb2_flush(smb_request_t *sr)
{
	smb_ofile_t *of = NULL;
	uint16_t StructSize;
	uint16_t reserved1;
	uint32_t reserved2;
	smb2fid_t smb2fid;
	uint32_t status;
	int rc = 0;

	/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 
 /*
  * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
+ * Copyright 2016 Syneto S.R.L. All rights reserved.
  */
 
 /*
@@ -23,7 +24,6 @@
 smb_sdrc_t
 smb2_flush(smb_request_t *sr)
 {
-	smb_ofile_t *of = NULL;
 	uint16_t StructSize;
 	uint16_t reserved1;
 	uint32_t reserved2;
@@ -51,14 +51,8 @@
 		smb2sr_put_error(sr, status);
 		return (SDRC_SUCCESS);
 	}
-	of = sr->fid_ofile;
 
-	/*
-	 * XXX - todo:
-	 * Flush named pipe should drain writes.
-	 */
-	if ((of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
-		(void) smb_fsop_commit(sr, of->f_cr, of->f_node);
+	smb_ofile_flush(sr, sr->fid_ofile);
 
 	/*
 	 * SMB2 Flush reply
```
