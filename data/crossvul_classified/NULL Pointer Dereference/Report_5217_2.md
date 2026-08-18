# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5217_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5217_2`)

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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * General Structures Layout
 * -------------------------
 *
 * This is a simplified diagram showing the relationship between most of the
 * main structures.
 *
 * +-------------------+
 * |     SMB_INFO      |
 * +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |     SESSION       |<----->|     SESSION       |......|      SESSION      |
 * +-------------------+       +-------------------+      +-------------------+
 *   |          |
 *   |          |
 *   |          v
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 /*
  * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
  * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
+ * Copyright 2016 Syneto S.R.L. All rights reserved.
  */
 
 /*
@@ -837,6 +838,27 @@
 }
 
 /*
+ * smb_ofile_flush
+ *
+ * If writes on this file are not synchronous, flush it using the NFSv3
+ * commit interface.
+ *
+ * XXX - todo: Flush named pipe should drain writes.
+ */
+void
+smb_ofile_flush(struct smb_request *sr, struct smb_ofile *of)
+{
+	switch (of->f_ftype) {
+	case SMB_FTYPE_DISK:
+		if ((of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
+			(void) smb_fsop_commit(sr, of->f_cr, of->f_node);
+		break;
+	default:
+		break;
+	}
+}
+
+/*
  * smb_ofile_is_open
  */
 boolean_t
```
