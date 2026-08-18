# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 290_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `290_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 23-63 of the vulnerable file.


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "addrtostr.h"
#include "extract.h"

#include "ip6.h"
#include "ipproto.h"

#include "udp.h"
#include "ah.h"

/*	NetBSD: icmp6.h,v 1.13 2000/08/03 16:30:37 itojun Exp 	*/
/*	$KAME: icmp6.h,v 1.22 2000/08/03 15:25:16 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,10 @@
 
 #include "udp.h"
 #include "ah.h"
+
+static const char icmp6_tstr[] = " [|icmp6]";
+static const char rpl_tstr[] = " [|rpl]";
+static const char mldv2_tstr[] = " [|mldv2]";
 
 /*	NetBSD: icmp6.h,v 1.13 2000/08/03 16:30:37 itojun Exp 	*/
 /*	$KAME: icmp6.h,v 1.22 2000/08/03 15:25:16 jinmei Exp $	*/
@@ -683,10 +687,11 @@
                 }
                 opt = (const struct rpl_dio_genoption *)(((const char *)opt) + optlen);
                 length -= optlen;
+                ND_TCHECK(opt->rpl_dio_len);
         }
         return;
 trunc:
-	ND_PRINT((ndo," [|truncated]"));
+	ND_PRINT((ndo, "%s", rpl_tstr));
 	return;
 }
 
@@ -715,7 +720,7 @@
         }
 	return;
 trunc:
-	ND_PRINT((ndo," [|truncated]"));
+	ND_PRINT((ndo, "%s", rpl_tstr));
 	return;
 }
 
@@ -756,7 +761,7 @@
 	return;
 
 trunc:
-	ND_PRINT((ndo," [|truncated]"));
+	ND_PRINT((ndo, "%s", rpl_tstr));
 	return;
 
 tooshort:
@@ -800,7 +805,7 @@
 	return;
 
 trunc:
-	ND_PRINT((ndo," [|dao-truncated]"));
+	ND_PRINT((ndo, "%s", rpl_tstr));
 	return;
 
 tooshort:
@@ -859,7 +864,7 @@
 
 #if 0
 trunc:
-	ND_PRINT((ndo," [|truncated]"));
+	ND_PRINT((ndo, "%s", rpl_tstr));
 	return;
 #endif
 
@@ -1157,7 +1162,7 @@
                 ND_PRINT((ndo,", length %u", length));
 	return;
 trunc:
-	ND_PRINT((ndo, "[|icmp6]"));
+	ND_PRINT((ndo, "%s", icmp6_tstr));
 }
 
 static const struct udphdr *
@@ -1381,8 +1386,8 @@
 	}
 	return;
 
- trunc:
-	ND_PRINT((ndo, "[ndp opt]"));
+trunc:
+	ND_PRINT((ndo, "%s", icmp6_tstr));
 	return;
 #undef ECHECK
 }
@@ -1457,7 +1462,7 @@
     }
     return;
 trunc:
-    ND_PRINT((ndo,"[|icmp6]"));
+    ND_PRINT((ndo, "%s", mldv2_tstr));
     return;
 }
 
@@ -1523,7 +1528,7 @@
     ND_PRINT((ndo,"]"));
     return;
 trunc:
-    ND_PRINT((ndo,"[|icmp6]"));
+    ND_PRINT((ndo, "%s", mldv2_tstr));
     return;
 }
 
@@ -1810,7 +1815,7 @@
 	return;
 
 trunc:
-	ND_PRINT((ndo, "[|icmp6]"));
+	ND_PRINT((ndo, "%s", icmp6_tstr));
 }
 
 static void
@@ -1945,7 +1950,7 @@
 	return;
 
 trunc:
-	ND_PRINT((ndo,"[|icmp6]"));
+	ND_PRINT((ndo, "%s", icmp6_tstr));
 }
 
 /*
```
