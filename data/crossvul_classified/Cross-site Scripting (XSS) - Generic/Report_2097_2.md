# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 2097_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2097_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 278-318 of the vulnerable file.

import java.util.Properties;
import java.util.Set;
import java.util.Stack;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import static java.util.logging.Level.SEVERE;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Root object of the system.
 *
 * @author Kohsuke Kawaguchi
 */
@ExportedBean
public class Jenkins extends AbstractCIBase implements ModifiableTopLevelItemGroup, StaplerProxy, StaplerFallback, ViewGroup, AccessControlled, DescriptorByNameOwner, ModelObjectWithContextMenu {
    private transient final Queue queue;

    /**
     * Stores various objects scoped to {@link Jenkins}.
     */
    public transient final Lookup lookup = new Lookup();

    /**
     * We update this field to the current version of Hudson whenever we save {@code config.xml}.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,7 +295,6 @@
 import static java.util.logging.Level.SEVERE;
 import java.util.logging.LogRecord;
 import java.util.logging.Logger;
-import java.util.regex.Pattern;
 import javax.annotation.CheckForNull;
 import javax.annotation.Nonnull;
 import javax.annotation.Nullable;
@@ -3417,9 +3416,9 @@
      */
     public void doIconSize( StaplerRequest req, StaplerResponse rsp ) throws IOException, ServletException {
         String qs = req.getQueryString();
-        if(qs==null || !ICON_SIZE.matcher(qs).matches())
+        if(qs==null)
             throw new ServletException();
-        Cookie cookie = new Cookie("iconSize", qs);
+        Cookie cookie = new Cookie("iconSize", Functions.validateIconSize(qs));
         cookie.setMaxAge(/* ~4 mo. */9999999); // #762
         rsp.addCookie(cookie);
         String ref = req.getHeader("Referer");
@@ -3964,8 +3963,6 @@
 
     private static final Logger LOGGER = Logger.getLogger(Jenkins.class.getName());
 
-    private static final Pattern ICON_SIZE = Pattern.compile("\\d+x\\d+");
-
     public static final PermissionGroup PERMISSIONS = Permission.HUDSON_PERMISSIONS;
     public static final Permission ADMINISTER = Permission.HUDSON_ADMINISTER;
     public static final Permission READ = new Permission(PERMISSIONS,"Read",Messages._Hudson_ReadPermission_Description(),Permission.READ,PermissionScope.JENKINS);
```
