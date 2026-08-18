# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5217_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5217_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 4-44 of the vulnerable file.

 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The flush SMB is sent to ensure all data and allocation information
 * for the corresponding file has been written to stable storage. This
 * is a synchronous request. The response should not be sent until the
 * writes are complete.
 *
 * The SmbFlush request is described in CIFS/1.0 1996 Section 3.9.14.
 *
 * CIFS/1.0 June 13, 1996
 * Heizer, et al
 * draft-heizer-cifs-v1-spec-00.txt
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>


static void smb_flush_file(struct smb_request *sr, struct smb_ofile *ofile);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,8 @@
 /*
  * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
  * Use is subject to license terms.
+ *
+ * Copyright 2016 Syneto S.R.L. All rights reserved.
  */
 
 /*
@@ -39,8 +41,6 @@
 #include <smbsrv/smb_kproto.h>
 #include <smbsrv/smb_fsops.h>
 
-
-static void smb_flush_file(struct smb_request *sr, struct smb_ofile *ofile);
 
 /*
  * smb_com_flush
@@ -90,15 +90,14 @@
 			    ERRDOS, ERRbadfid);
 			return (SDRC_ERROR);
 		}
-
-		smb_flush_file(sr, sr->fid_ofile);
+		smb_ofile_flush(sr, sr->fid_ofile);
 	} else {
 		flist = &sr->tid_tree->t_ofile_list;
 		smb_llist_enter(flist, RW_READER);
 		file = smb_llist_head(flist);
 		while (file) {
 			mutex_enter(&file->f_mutex);
-			smb_flush_file(sr, file);
+			smb_ofile_flush(sr, file);
 			mutex_exit(&file->f_mutex);
 			file = smb_llist_next(flist, file);
 		}
@@ -108,19 +107,3 @@
 	rc = smbsr_encode_empty_result(sr);
 	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
 }
-
-
-/*
- * smb_flush_file
- *
- * If writes on this file are not synchronous, flush it using the NFSv3
- * commit interface.
- */
-static void
-smb_flush_file(struct smb_request *sr, struct smb_ofile *ofile)
-{
-	sr->user_cr = smb_ofile_getcred(ofile);
-
-	if ((ofile->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
-		(void) smb_fsop_commit(sr, sr->user_cr, ofile->f_node);
-}
```
