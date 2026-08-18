# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5222_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
   Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.

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

/* Describe, check and repair of MyISAM tables */

/*
  About checksum calculation.

  There are two types of checksums. Table checksum and row checksum.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
-   Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.
+   Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -1512,7 +1512,7 @@
 	/* Save new datafile-name in temp_filename */
 
 int mi_repair(MI_CHECK *param, register MI_INFO *info,
-	      char * name, int rep_quick)
+	      char * name, int rep_quick, my_bool no_copy_stat)
 {
   int error,got_error;
   ha_rows start_records,new_header_length;
@@ -1726,6 +1726,11 @@
     /* Replace the actual file with the temporary file */
     if (new_file >= 0)
     {
+      myf flags= 0;
+      if (param->testflag & T_BACKUP_DATA)
+        flags |= MY_REDEL_MAKE_BACKUP;
+      if (no_copy_stat)
+        flags |= MY_REDEL_NO_COPY_STAT;
       mysql_file_close(new_file, MYF(0));
       info->dfile=new_file= -1;
       /*
@@ -1744,8 +1749,7 @@
         info->s->file_map= NULL;
       }
       if (change_to_newfile(share->data_file_name, MI_NAME_DEXT, DATA_TMP_EXT,
-			    (param->testflag & T_BACKUP_DATA ?
-			     MYF(MY_REDEL_MAKE_BACKUP): MYF(0))) ||
+                            flags) ||
 	  mi_open_datafile(info,share,name,-1))
 	got_error=1;
 
@@ -1933,7 +1937,8 @@
 
 	/* Sort index for more efficent reads */
 
-int mi_sort_index(MI_CHECK *param, register MI_INFO *info, char * name)
+int mi_sort_index(MI_CHECK *param, register MI_INFO *info, char * name,
+                  my_bool no_copy_stat)
 {
   reg2 uint key;
   reg1 MI_KEYDEF *keyinfo;
@@ -2004,7 +2009,7 @@
   share->kfile = -1;
   (void) mysql_file_close(new_file, MYF(MY_WME));
   if (change_to_newfile(share->index_file_name, MI_NAME_IEXT, INDEX_TMP_EXT,
-			MYF(0)) ||
+			no_copy_stat ? MYF(MY_REDEL_NO_COPY_STAT) : MYF(0)) ||
       mi_open_keyfile(share))
     goto err2;
   info->lock_type= F_UNLCK;			/* Force mi_readinfo to lock */
@@ -2209,6 +2214,8 @@
     info		MyISAM handler to repair
     name		Name of table (for warnings)
     rep_quick		set to <> 0 if we should not change data file
+    no_copy_stat        Don't copy file stats from old to new file,
+                        assume that new file was created with correct stats
 
   RESULT
     0	ok
@@ -2216,7 +2223,7 @@
 */
 
 int mi_repair_by_sort(MI_CHECK *param, register MI_INFO *info,
-		      const char * name, int rep_quick)
+		      const char * name, int rep_quick, my_bool no_copy_stat)
 {
   int got_error;
   uint i;
@@ -2543,11 +2550,15 @@
     /* Replace the actual file with the temporary file */
     if (new_file >= 0)
     {
+      myf flags= 0;
+      if (param->testflag & T_BACKUP_DATA)
+        flags |= MY_REDEL_MAKE_BACKUP;
+      if (no_copy_stat)
+        flags |= MY_REDEL_NO_COPY_STAT;
       mysql_file_close(new_file, MYF(0));
       info->dfile=new_file= -1;
       if (change_to_newfile(share->data_file_name,MI_NAME_DEXT, DATA_TMP_EXT,
-			    (param->testflag & T_BACKUP_DATA ?
-			     MYF(MY_REDEL_MAKE_BACKUP): MYF(0))) ||
+                            flags) ||
 	  mi_open_datafile(info,share,name,-1))
 	got_error=1;
     }
@@ -2595,6 +2606,8 @@
     info		MyISAM handler to repair
     name		Name of table (for warnings)
     rep_quick		set to <> 0 if we should not change data file
+    no_copy_stat        Don't copy file stats from old to new file,
+                        assume that new file was created with correct stats
 
   DESCRIPTION
     Same as mi_repair_by_sort but do it multithreaded
@@ -2629,7 +2642,7 @@
 */
 
 int mi_repair_parallel(MI_CHECK *param, register MI_INFO *info,
-			const char * name, int rep_quick)
+                       const char * name, int rep_quick, my_bool no_copy_stat)
 {
   int got_error;
   uint i,key, total_key_length, istep;
@@ -3076,11 +3089,15 @@
     /* Replace the actual file with the temporary file */
     if (new_file >= 0)
     {
+      myf flags= 0;
+      if (param->testflag & T_BACKUP_DATA)
+        flags |= MY_REDEL_MAKE_BACKUP;
+      if (no_copy_stat)
+        flags |= MY_REDEL_NO_COPY_STAT;
       mysql_file_close(new_file, MYF(0));
       info->dfile=new_file= -1;
       if (change_to_newfile(share->data_file_name, MI_NAME_DEXT, DATA_TMP_EXT,
-			    (param->testflag & T_BACKUP_DATA ?
-			     MYF(MY_REDEL_MAKE_BACKUP): MYF(0))) ||
+			    flags) ||
 	  mi_open_datafile(info,share,name,-1))
 	got_error=1;
     }
```
