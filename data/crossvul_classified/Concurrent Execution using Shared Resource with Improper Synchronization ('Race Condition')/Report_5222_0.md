# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5222_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */

#ifndef _my_sys_h
#define _my_sys_h

#include "my_global.h"                  /* C_MODE_START, C_MODE_END */

C_MODE_START
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
+/* Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -83,6 +83,7 @@
 #define MY_RESOLVE_LINK 128	/* my_realpath(); Only resolve links */
 #define MY_HOLD_ORIGINAL_MODES 128  /* my_copy() holds to file modes */
 #define MY_REDEL_MAKE_BACKUP 256
+#define MY_REDEL_NO_COPY_STAT 512 /* my_redel() doesn't call my_copystat() */
 #define MY_SEEK_NOT_DONE 32	/* my_lock may have to do a seek */
 #define MY_DONT_WAIT	64	/* my_lock() don't wait if can't lock */
 #define MY_ZEROFILL	32	/* my_malloc(), fill array with zero */
```
