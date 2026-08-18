# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4992_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4992_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 1-38 of the vulnerable file.

/**
 * Copyright (c) 2013--2014 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */

package com.redhat.rhn.frontend.action.groups;

import com.redhat.rhn.domain.server.ManagedServerGroup;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnAction;
import com.redhat.rhn.frontend.struts.RhnHelper;
import com.redhat.rhn.manager.system.ServerGroupManager;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * DeleteGroupAction
 * @version 1.0
 */
public class DeleteGroupAction extends RhnAction {
    private static final String DELETED_MESSAGE_KEY = "systemgroup.delete.deleted";
    /** {@inheritDoc} */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,18 +15,19 @@
 
 package com.redhat.rhn.frontend.action.groups;
 
+import javax.servlet.http.HttpServletRequest;
+import javax.servlet.http.HttpServletResponse;
+
+import org.apache.commons.lang.StringEscapeUtils;
+import org.apache.struts.action.ActionForm;
+import org.apache.struts.action.ActionForward;
+import org.apache.struts.action.ActionMapping;
+
 import com.redhat.rhn.domain.server.ManagedServerGroup;
 import com.redhat.rhn.frontend.struts.RequestContext;
 import com.redhat.rhn.frontend.struts.RhnAction;
 import com.redhat.rhn.frontend.struts.RhnHelper;
 import com.redhat.rhn.manager.system.ServerGroupManager;
-
-import org.apache.struts.action.ActionForm;
-import org.apache.struts.action.ActionForward;
-import org.apache.struts.action.ActionMapping;
-
-import javax.servlet.http.HttpServletRequest;
-import javax.servlet.http.HttpServletResponse;
 
 
 /**
@@ -36,6 +37,7 @@
 public class DeleteGroupAction extends RhnAction {
     private static final String DELETED_MESSAGE_KEY = "systemgroup.delete.deleted";
     /** {@inheritDoc} */
+    @Override
     public ActionForward execute(ActionMapping mapping,
                                  ActionForm formIn,
                                  HttpServletRequest request,
@@ -43,9 +45,9 @@
         RequestContext context = new RequestContext(request);
         ManagedServerGroup serverGroup = context.lookupAndBindServerGroup();
         if (context.isSubmitted()) {
-            String [] params = {serverGroup.getName()};
             ServerGroupManager manager = ServerGroupManager.getInstance();
             manager.remove(context.getCurrentUser(), serverGroup);
+            String [] params = {StringEscapeUtils.escapeHtml(serverGroup.getName())};
             getStrutsDelegate().saveMessage(DELETED_MESSAGE_KEY, params, request);
             return mapping.findForward("success");
         }
```
