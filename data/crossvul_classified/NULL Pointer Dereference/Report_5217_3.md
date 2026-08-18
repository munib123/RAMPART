# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5217_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5217_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.

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
 * Function prototypes for the SMB module.
 */

#ifndef _SMB_KPROTO_H_
#define	_SMB_KPROTO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/cred.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 /*
  * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
  * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
+ * Copyright 2016 Syneto S.R.L.  All rights reserved.
  */
 
 /*
@@ -673,6 +674,7 @@
 void smb_ofile_delete(void *);
 uint32_t smb_ofile_access(smb_ofile_t *, cred_t *, uint32_t);
 int smb_ofile_seek(smb_ofile_t *, ushort_t, int32_t, uint32_t *);
+void smb_ofile_flush(smb_request_t *, smb_ofile_t *);
 boolean_t smb_ofile_hold(smb_ofile_t *);
 void smb_ofile_release(smb_ofile_t *);
 void smb_ofile_request_complete(smb_ofile_t *);
```
