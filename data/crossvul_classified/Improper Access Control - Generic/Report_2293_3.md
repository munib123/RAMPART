# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 2293_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2293_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

 * limitations under the License.
 */

package org.uberfire.security.server;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.uberfire.security.Resource;
import org.uberfire.security.ResourceManager;
import org.uberfire.security.Role;
import org.uberfire.security.impl.RoleImpl;
import org.uberfire.security.server.util.AntPathMatcher;
import org.yaml.snakeyaml.Yaml;

import static java.util.Collections.*;
import static org.uberfire.commons.validation.PortablePreconditions.checkNotNull;
import static org.uberfire.commons.validation.Preconditions.*;
import static org.uberfire.security.server.SecurityConstants.*;

public class URLResourceManager implements ResourceManager {

    private static final AntPathMatcher ANT_PATH_MATCHER = new AntPathMatcher();
    private static final Collection<Class<? extends Resource>> SUPPORTED_TYPES = new ArrayList<Class<? extends Resource>>( 1 ) {{
        add( URLResource.class );
    }};

    private static final String DEFAULT_CONFIG = "exclude:\n" +
            "   - /*.ico\n" +
            "   - /image/**\n" +
            "   - /css/**";

    private String configFile = URL_FILTER_CONFIG_YAML;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
 import org.uberfire.security.ResourceManager;
 import org.uberfire.security.Role;
 import org.uberfire.security.impl.RoleImpl;
-import org.uberfire.security.server.util.AntPathMatcher;
+import org.uberfire.commons.regex.util.AntPathMatcher;
 import org.yaml.snakeyaml.Yaml;
 
 import static java.util.Collections.*;
```
