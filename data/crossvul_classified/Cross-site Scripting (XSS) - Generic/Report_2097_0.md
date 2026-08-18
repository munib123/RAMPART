# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 2097_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2097_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 106-146 of the vulnerable file.

import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;

/**
 * Utility functions used in views.
 *
 * <p>
 * An instance of this class is created for each request and made accessible
 * from view pages via the variable 'h' (h stands for Hudson.)
 *
 * @author Kohsuke Kawaguchi
 */
public class Functions {
    private static volatile int globalIota = 0;
    private int iota;

    public Functions() {
        iota = globalIota;
        // concurrent requests can use the same ID --- we are just trying to
        // prevent the same user from seeing the same ID repeatedly.
        globalIota+=1000;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,6 +123,8 @@
 import java.util.logging.SimpleFormatter;
 import java.util.regex.Pattern;
 import org.apache.commons.lang.StringUtils;
+import org.kohsuke.accmod.Restricted;
+import org.kohsuke.accmod.restrictions.NoExternalUse;
 
 /**
  * Utility functions used in views.
@@ -424,6 +426,15 @@
         Cookie c = getCookie(req, name);
         if(c==null || c.getValue()==null) return defaultValue;
         return c.getValue();
+    }
+
+    private static final Pattern ICON_SIZE = Pattern.compile("\\d+x\\d+");
+    @Restricted(NoExternalUse.class)
+    public static String validateIconSize(String iconSize) throws SecurityException {
+        if (!ICON_SIZE.matcher(iconSize).matches()) {
+            throw new SecurityException("invalid iconSize");
+        }
+        return iconSize;
     }
 
     /**
```
