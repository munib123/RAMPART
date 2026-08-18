# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5222_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include "mysys_priv.h"
#include <my_dir.h>
#include <m_string.h>
#include "mysys_err.h"
#if defined(HAVE_UTIME_H)
#include <utime.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
+/* Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -35,6 +35,9 @@
 
 	  if MY_REDEL_MAKE_COPY is given, then the orginal file
 	  is renamed to org_name-'current_time'.BAK
+
+          if MY_REDEL_NO_COPY_STAT is given, stats are not copied
+          from org_name to tmp_name.
 	*/
 
 #define REDEL_EXT ".BAK"
@@ -46,8 +49,11 @@
   DBUG_PRINT("my",("org_name: '%s' tmp_name: '%s'  MyFlags: %d",
 		   org_name,tmp_name,MyFlags));
 
-  if (my_copystat(org_name,tmp_name,MyFlags) < 0)
-    goto end;
+  if (!(MyFlags & MY_REDEL_NO_COPY_STAT))
+  {
+    if (my_copystat(org_name,tmp_name,MyFlags) < 0)
+      goto end;
+  }
   if (MyFlags & MY_REDEL_MAKE_BACKUP)
   {
     char name_buff[FN_REFLEN+20];    
```
