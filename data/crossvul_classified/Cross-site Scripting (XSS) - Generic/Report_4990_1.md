# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4990_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4990_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

/**
 * Copyright (c) 2009--2014 Red Hat, Inc.
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

package com.redhat.rhn.frontend.nav;

import com.redhat.rhn.frontend.html.HtmlTag;

import java.util.Map;
import java.util.StringTokenizer;

/**
 * DialognavRenderer - renders a navigation bar
 *
 * Renders the navigation inside the content, which is implemented
 * as rows of Twitter Bootstrap tabs (nav-tabs)
 *
 * The navigation is enclosed in a div styled with class
 * 'spacewalk-content-nav' and the individual rows can be styled by
 * ul:nth-child selectors.
 *
 * @version $Rev$
 */

public class DialognavRenderer extends Renderable {
    private final StringBuffer titleBuf;
    /**
     * Public constructor
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,10 +15,12 @@
 
 package com.redhat.rhn.frontend.nav;
 
-import com.redhat.rhn.frontend.html.HtmlTag;
-
 import java.util.Map;
 import java.util.StringTokenizer;
+
+import org.apache.commons.lang.StringEscapeUtils;
+
+import com.redhat.rhn.frontend.html.HtmlTag;
 
 /**
  * DialognavRenderer - renders a navigation bar
@@ -135,7 +137,8 @@
                 // if currentVar is null, values will be null too, so we can
                 // just check values.
                 if (values != null) {
-                    formVars.append(currentVar + "=" + values[0]);
+                    formVars.append(currentVar + "=" +
+                             StringEscapeUtils.escapeHtml(values[0]));
                 }
             }
             href += formVars.toString();
```
