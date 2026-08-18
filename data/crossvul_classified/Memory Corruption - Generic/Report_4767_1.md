# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4767_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4767_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: monitor.h,v 1.19 2015/01/19 19:52:16 markus Exp $ */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: monitor.h,v 1.19 2015/01/19 19:52:16 markus Exp $ */
+/* $OpenBSD: monitor.h,v 1.20 2016/09/28 16:33:07 djm Exp $ */
 
 /*
  * Copyright 2002 Niels Provos <provos@citi.umich.edu>
@@ -58,21 +58,17 @@
 	MONITOR_REQ_TERM = 50,
 };
 
-struct mm_master;
 struct monitor {
 	int			 m_recvfd;
 	int			 m_sendfd;
 	int			 m_log_recvfd;
 	int			 m_log_sendfd;
-	struct mm_master	*m_zback;
-	struct mm_master	*m_zlib;
 	struct kex		**m_pkex;
 	pid_t			 m_pid;
 };
 
 struct monitor *monitor_init(void);
 void monitor_reinit(struct monitor *);
-void monitor_sync(struct monitor *);
 
 struct Authctxt;
 void monitor_child_preauth(struct Authctxt *, struct monitor *);
```
