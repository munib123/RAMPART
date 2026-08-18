# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 3865_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3865_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-24 of the vulnerable file.

/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.service.account;

import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AccountConstants;
import com.zimbra.common.soap.Element;
import com.zimbra.cs.account.Account;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 /*
  * ***** BEGIN LICENSE BLOCK *****
  * Zimbra Collaboration Suite Server
- * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
+ * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2013, 2014, 2016, 2020 Synacor, Inc.
  *
  * This program is free software: you can redistribute it and/or modify it under
  * the terms of the GNU General Public License as published by the Free Software Foundation,
@@ -57,8 +57,14 @@
         params.setLimit(account.getContactAutoCompleteMaxResults());
         params.setNeedCanExpand(needCanExpand);
         params.setResponseName(AccountConstants.AUTO_COMPLETE_GAL_RESPONSE);
-        if (galAcctId != null)
-            params.setGalSyncAccount(Provisioning.getInstance().getAccountById(galAcctId));
+        if (galAcctId != null) {
+            Account galAccount = Provisioning.getInstance().getAccountById(galAcctId);
+            if (galAccount != null && (!account.getDomainId().equals(galAccount.getDomainId()))) {
+                throw ServiceException
+                    .PERM_DENIED("can not access galsync account of different domain");
+            }
+            params.setGalSyncAccount(galAccount);
+        }
         GalSearchControl gal = new GalSearchControl(params);
         gal.autocomplete();
         return params.getResultCallback().getResponse();
```
