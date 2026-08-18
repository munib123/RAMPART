# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in cpp
**Pair ID:** 5222_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```cpp
Lines 1-22 of the vulnerable file.

/*
   Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

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


#ifdef USE_PRAGMA_IMPLEMENTATION
#pragma implementation				// gcc: Class implementation
#endif

#define MYSQL_SERVER 1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
-   Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.
+   Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -1091,24 +1091,36 @@
         /* TODO: respect myisam_repair_threads variable */
         my_snprintf(buf, 40, "Repair with %d threads", my_count_bits(key_map));
         thd_proc_info(thd, buf);
+        /*
+          The new file is created with the right stats, so we can skip
+          copying file stats from old to new.
+        */
         error = mi_repair_parallel(&param, file, fixed_name,
-            param.testflag & T_QUICK);
+                                   param.testflag & T_QUICK, TRUE);
         thd_proc_info(thd, "Repair done"); // to reset proc_info, as
                                       // it was pointing to local buffer
       }
       else
       {
         thd_proc_info(thd, "Repair by sorting");
+        /*
+          The new file is created with the right stats, so we can skip
+          copying file stats from old to new.
+        */
         error = mi_repair_by_sort(&param, file, fixed_name,
-            param.testflag & T_QUICK);
+                                  param.testflag & T_QUICK, TRUE);
       }
     }
     else
     {
       thd_proc_info(thd, "Repair with keycache");
       param.testflag &= ~T_REP_BY_SORT;
+      /*
+        The new file is created with the right stats, so we can skip
+        copying file stats from old to new.
+      */
       error=  mi_repair(&param, file, fixed_name,
-			param.testflag & T_QUICK);
+			param.testflag & T_QUICK, TRUE);
     }
 #ifdef HAVE_MMAP
     if (remap)
@@ -1124,7 +1136,11 @@
     {
       optimize_done=1;
       thd_proc_info(thd, "Sorting index");
-      error=mi_sort_index(&param,file,fixed_name);
+      /*
+        The new file is created with the right stats, so we can skip
+        copying file stats from old to new.
+      */
+      error=mi_sort_index(&param,file,fixed_name, TRUE);
     }
     if (!statistics_done && (local_testflag & T_STATISTICS))
     {
```
