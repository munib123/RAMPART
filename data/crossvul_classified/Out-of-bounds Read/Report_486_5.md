# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 486_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `486_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-24 of the vulnerable file.

/*  -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Support for the Matrox "lspci" channel
   Copyright (C) 2005 Matrox Graphics Inc. 

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "rdesktop.h"
#include <sys/types.h>
#include <unistd.h>

static VCHANNEL *lspci_channel;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,8 @@
 /*  -*- c-basic-offset: 8 -*-
    rdesktop: A Remote Desktop Protocol client.
    Support for the Matrox "lspci" channel
-   Copyright (C) 2005 Matrox Graphics Inc. 
+   Copyright (C) 2005 Matrox Graphics Inc.
+   Copyright 2018 Henrik Andersson <hean01@cendio.se> for Cendio AB
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
@@ -134,6 +135,12 @@
 	unsigned int pkglen;
 	static char *rest = NULL;
 	char *buf;
+	struct stream packet = *s;
+
+	if (!s_check(s))
+	{
+		rdp_protocol_error("lspci_process(), stream is in unstable state", &packet);
+	}
 
 	pkglen = s->end - s->p;
 	/* str_handle_lines requires null terminated strings */
```
