# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5222_5
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5222_5`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

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

/* Describe, check and repair of MyISAM tables */

#include "fulltext.h"

#include <m_ctype.h>
#include <stdarg.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.
+/* Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -993,14 +993,18 @@
 				info->s->state.key_map,
 				param->force_sort))
 	{
+          /*
+            The new file might not be created with the right stats depending
+            on how myisamchk is run, so we must copy file stats from old to new.
+          */
           if (param->testflag & T_REP_BY_SORT)
-            error=mi_repair_by_sort(param,info,filename,rep_quick);
+            error= mi_repair_by_sort(param, info, filename, rep_quick, FALSE);
           else
-            error=mi_repair_parallel(param,info,filename,rep_quick);
+            error= mi_repair_parallel(param, info, filename, rep_quick, FALSE);
 	  state_updated=1;
 	}
 	else if (param->testflag & T_REP_ANY)
-	  error=mi_repair(param, info,filename,rep_quick);
+	  error= mi_repair(param, info, filename, rep_quick, FALSE);
       }
       if (!error && param->testflag & T_SORT_RECORDS)
       {
@@ -1040,12 +1044,12 @@
 	  {
 	    if (param->verbose)
 	      puts("Table had a compressed index;  We must now recreate the index");
-	    error=mi_repair_by_sort(param,info,filename,1);
+	    error= mi_repair_by_sort(param, info, filename, 1, FALSE);
 	  }
 	}
       }
       if (!error && param->testflag & T_SORT_INDEX)
-	error=mi_sort_index(param,info,filename);
+	error= mi_sort_index(param, info, filename, FALSE);
       if (!error)
 	share->state.changed&= ~(STATE_CHANGED | STATE_CRASHED |
 				 STATE_CRASHED_ON_REPAIR);
```
