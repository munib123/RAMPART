# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4767_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4767_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: monitor.c,v 1.165 2016/09/05 13:57:31 djm Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2002 Markus Friedl <markus@openbsd.org>
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
-/* $OpenBSD: monitor.c,v 1.165 2016/09/05 13:57:31 djm Exp $ */
+/* $OpenBSD: monitor.c,v 1.166 2016/09/28 16:33:06 djm Exp $ */
 /*
  * Copyright 2002 Niels Provos <provos@citi.umich.edu>
  * Copyright 2002 Markus Friedl <markus@openbsd.org>
@@ -70,7 +70,6 @@
 #include "misc.h"
 #include "servconf.h"
 #include "monitor.h"
-#include "monitor_mm.h"
 #ifdef GSSAPI
 #include "ssh-gss.h"
 #endif
@@ -333,31 +332,6 @@
 
 	for (;;)
 		monitor_read(pmonitor, mon_dispatch, NULL);
-}
-
-void
-monitor_sync(struct monitor *pmonitor)
-{
-	if (options.compression) {
-		/* The member allocation is not visible, so sync it */
-		mm_share_sync(&pmonitor->m_zlib, &pmonitor->m_zback);
-	}
-}
-
-/* Allocation functions for zlib */
-static void *
-mm_zalloc(struct mm_master *mm, u_int ncount, u_int size)
-{
-	if (size == 0 || ncount == 0 || ncount > SIZE_MAX / size)
-		fatal("%s: mm_zalloc(%u, %u)", __func__, ncount, size);
-
-	return mm_malloc(mm, size * ncount);
-}
-
-static void
-mm_zfree(struct mm_master *mm, void *address)
-{
-	mm_free(mm, address);
 }
 
 static int
@@ -1292,13 +1266,6 @@
 		kex->host_key_index=&get_hostkey_index;
 		kex->sign = sshd_hostkey_sign;
 	}
-
-	/* Update with new address */
-	if (options.compression) {
-		ssh_packet_set_compress_hooks(ssh, pmonitor->m_zlib,
-		    (ssh_packet_comp_alloc_func *)mm_zalloc,
-		    (ssh_packet_comp_free_func *)mm_zfree);
-	}
 }
 
 /* This function requries careful sanity checking */
@@ -1351,23 +1318,10 @@
 struct monitor *
 monitor_init(void)
 {
-	struct ssh *ssh = active_state;			/* XXX */
 	struct monitor *mon;
 
 	mon = xcalloc(1, sizeof(*mon));
-
 	monitor_openfds(mon, 1);
-
-	/* Used to share zlib space across processes */
-	if (options.compression) {
-		mon->m_zback = mm_create(NULL, MM_MEMSIZE);
-		mon->m_zlib = mm_create(mon->m_zback, 20 * MM_MEMSIZE);
-
-		/* Compression needs to share state across borders */
-		ssh_packet_set_compress_hooks(ssh, mon->m_zlib,
-		    (ssh_packet_comp_alloc_func *)mm_zalloc,
-		    (ssh_packet_comp_free_func *)mm_zfree);
-	}
 
 	return mon;
 }
```
