# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5222_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
   Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

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

/* This file should be included when using myisam_funktions */

#ifndef _myisam_h
#define _myisam_h
#ifdef	__cplusplus
extern "C" {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
-   Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
+   Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -426,12 +426,13 @@
 int chk_key(MI_CHECK *param, MI_INFO *info);
 int chk_data_link(MI_CHECK *param, MI_INFO *info,int extend);
 int mi_repair(MI_CHECK *param, register MI_INFO *info,
-	      char * name, int rep_quick);
-int mi_sort_index(MI_CHECK *param, register MI_INFO *info, char * name);
+	      char * name, int rep_quick, my_bool no_copy_stat);
+int mi_sort_index(MI_CHECK *param, register MI_INFO *info, char * name,
+                  my_bool no_copy_stat);
 int mi_repair_by_sort(MI_CHECK *param, register MI_INFO *info,
-		      const char * name, int rep_quick);
+		      const char * name, int rep_quick, my_bool no_copy_stat);
 int mi_repair_parallel(MI_CHECK *param, register MI_INFO *info,
-		      const char * name, int rep_quick);
+                       const char * name, int rep_quick, my_bool no_copy_stat);
 int change_to_newfile(const char * filename, const char * old_ext,
 		      const char * new_ext, myf myflags);
 int lock_file(MI_CHECK *param, File file, my_off_t start, int lock_type,
```
