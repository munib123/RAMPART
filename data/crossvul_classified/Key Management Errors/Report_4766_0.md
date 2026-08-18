# CrossVul Fix Pair: Key Management Errors in c
**Pair ID:** 4766_0
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4766_0`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: authfile.c,v 1.121 2016/04/09 12:39:30 djm Exp $ */
/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
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
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: authfile.c,v 1.121 2016/04/09 12:39:30 djm Exp $ */
+/* $OpenBSD: authfile.c,v 1.122 2016/11/25 23:24:45 djm Exp $ */
 /*
  * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
  *
@@ -98,13 +98,25 @@
 	u_char buf[1024];
 	size_t len;
 	struct stat st;
-	int r;
+	int r, dontmax = 0;
 
 	if (fstat(fd, &st) < 0)
 		return SSH_ERR_SYSTEM_ERROR;
 	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
 	    st.st_size > MAX_KEY_FILE_SIZE)
 		return SSH_ERR_INVALID_FORMAT;
+	/*
+	 * Pre-allocate the buffer used for the key contents and clamp its
+	 * maximum size. This ensures that key contents are never leaked via
+	 * implicit realloc() in the sshbuf code.
+	 */
+	if ((st.st_mode & S_IFREG) == 0 || st.st_size <= 0) {
+		st.st_size = 64*1024; /* 64k should be enough for anyone :) */
+		dontmax = 1;
+	}
+	if ((r = sshbuf_allocate(blob, st.st_size)) != 0 ||
+	    (dontmax && (r = sshbuf_set_max_size(blob, st.st_size)) != 0))
+		return r;
 	for (;;) {
 		if ((len = atomicio(read, fd, buf, sizeof(buf))) == 0) {
 			if (errno == EPIPE)
```
