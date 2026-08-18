# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 4990_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4990_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 1-46 of the vulnerable file.

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
package com.redhat.rhn.common.localization;

import com.redhat.rhn.common.conf.Config;
import com.redhat.rhn.common.conf.ConfigDefaults;
import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.db.datasource.ModeFactory;
import com.redhat.rhn.common.db.datasource.SelectMode;
import com.redhat.rhn.common.util.StringUtil;
import com.redhat.rhn.frontend.context.Context;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;

import java.text.Collator;
import java.text.DateFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.StringTokenizer;
import java.util.TimeZone;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,17 +13,6 @@
  * in this software or its documentation.
  */
 package com.redhat.rhn.common.localization;
-
-import com.redhat.rhn.common.conf.Config;
-import com.redhat.rhn.common.conf.ConfigDefaults;
-import com.redhat.rhn.common.db.datasource.DataResult;
-import com.redhat.rhn.common.db.datasource.ModeFactory;
-import com.redhat.rhn.common.db.datasource.SelectMode;
-import com.redhat.rhn.common.util.StringUtil;
-import com.redhat.rhn.frontend.context.Context;
-
-import org.apache.commons.lang.StringEscapeUtils;
-import org.apache.log4j.Logger;
 
 import java.text.Collator;
 import java.text.DateFormat;
@@ -47,6 +36,17 @@
 import java.util.TreeMap;
 import java.util.TreeSet;
 
+import org.apache.commons.lang.StringEscapeUtils;
+import org.apache.log4j.Logger;
+
+import com.redhat.rhn.common.conf.Config;
+import com.redhat.rhn.common.conf.ConfigDefaults;
+import com.redhat.rhn.common.db.datasource.DataResult;
+import com.redhat.rhn.common.db.datasource.ModeFactory;
+import com.redhat.rhn.common.db.datasource.SelectMode;
+import com.redhat.rhn.common.util.StringUtil;
+import com.redhat.rhn.frontend.context.Context;
+
 /**
  * Localization service class to simplify the job for producing localized
  * (translated) strings within the product.
@@ -368,7 +368,7 @@
         if (exceptionMode) {
             throw new IllegalArgumentException(message);
         }
-        return "**" + messageId + "**";
+        return StringEscapeUtils.escapeHtml("**" + messageId + "**");
     }
 
     /**
```
