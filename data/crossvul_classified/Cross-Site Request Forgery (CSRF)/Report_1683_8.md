# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in c
**Pair ID:** 1683_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1683_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/* UIxObjectActions.h - this file is part of SOGo
 *
 * Copyright (C) 2007 Inverse inc.
 *
 * Author: Wolfgang Sourdeau <wsourdeau@inverse.ca>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef UIXOBJECTACTIONS_H
#define UIXOBJECTACTIONS_H

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,6 @@
 /* UIxObjectActions.h - this file is part of SOGo
  *
- * Copyright (C) 2007 Inverse inc.
- *
- * Author: Wolfgang Sourdeau <wsourdeau@inverse.ca>
+ * Copyright (C) 2007-2016 Inverse inc.
  *
  * This file is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
@@ -23,10 +21,11 @@
 #ifndef UIXOBJECTACTIONS_H
 #define UIXOBJECTACTIONS_H
 
+#include "SOGoDirectAction.h"
 
 @class WOResponse;
 
-@interface UIxObjectActions : WODirectAction
+@interface UIxObjectActions : SOGoDirectAction
 
 - (WOResponse *) addUserInAclsAction;
 
```
