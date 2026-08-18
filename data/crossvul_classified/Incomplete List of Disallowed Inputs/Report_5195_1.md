# CrossVul Fix Pair: Incomplete List of Disallowed Inputs in c
**Pair ID:** 5195_1
**Vulnerability Class:** Incomplete List of Disallowed Inputs
**CWE:** CWE-184
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5195_1`)

## Vulnerability Information & PoC

## Description
Incomplete List of Disallowed Inputs - Developers often try to protect their products against malicious input by performing tests against inputs that are known to be bad, such as special characters that can invoke new commands.

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

/* SOGoUserSettings.h - this file is part of SOGo
 *
 * Copyright (C) 2009-2014 Inverse inc.
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

#ifndef SOGOUSERSETTINGS_H
#define SOGOUSERSETTINGS_H

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 /* SOGoUserSettings.h - this file is part of SOGo
  *
- * Copyright (C) 2009-2014 Inverse inc.
+ * Copyright (C) 2009-2016 Inverse inc.
  *
  * This file is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
@@ -33,6 +33,7 @@
 
 - (NSArray *) subscribedCalendars;
 - (NSArray *) subscribedAddressBooks;
+- (NSString *) userSalt;
 
 @end
 
```
