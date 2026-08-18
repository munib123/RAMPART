# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4765_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4765_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: serverloop.c,v 1.188 2016/11/30 03:00:05 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Server main loop for handling the interactive session.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: serverloop.c,v 1.188 2016/11/30 03:00:05 djm Exp $ */
+/* $OpenBSD: serverloop.c,v 1.189 2016/12/14 00:36:34 djm Exp $ */
 /*
  * Author: Tatu Ylonen <ylo@cs.hut.fi>
  * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
@@ -472,7 +472,8 @@
 
 	/* XXX fine grained permissions */
 	if ((options.allow_streamlocal_forwarding & FORWARD_LOCAL) != 0 &&
-	    !no_port_forwarding_flag && !options.disable_forwarding) {
+	    !no_port_forwarding_flag && !options.disable_forwarding &&
+	    use_privsep) {
 		c = channel_connect_to_path(target,
 		    "direct-streamlocal@openssh.com", "direct-streamlocal");
 	} else {
@@ -748,7 +749,8 @@
 
 		/* check permissions */
 		if ((options.allow_streamlocal_forwarding & FORWARD_REMOTE) == 0
-		    || no_port_forwarding_flag || options.disable_forwarding) {
+		    || no_port_forwarding_flag || options.disable_forwarding ||
+		    !use_privsep) {
 			success = 0;
 			packet_send_debug("Server has disabled port forwarding.");
 		} else {
```
