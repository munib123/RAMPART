# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5221_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5221_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/* Copyright (c) 2000, 2013, Oracle and/or its affiliates.
   Copyright (c) 2010, 2013, Monty Program Ab.

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
@@ -1,5 +1,5 @@
 /* Copyright (c) 2000, 2013, Oracle and/or its affiliates.
-   Copyright (c) 2010, 2013, Monty Program Ab.
+   Copyright (c) 2010, 2016, Monty Program Ab.
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -246,7 +246,7 @@
 extern ulong	my_default_record_cache_size;
 extern my_bool  my_disable_locking, my_disable_async_io,
                 my_disable_flush_key_blocks, my_disable_symlinks;
-extern my_bool my_disable_sync;
+extern my_bool my_disable_sync, my_disable_copystat_in_redel;
 extern char	wild_many,wild_one,wild_prefix;
 extern const char *charsets_dir;
 /* from default.c */
```
