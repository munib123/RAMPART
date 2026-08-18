# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 1545_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1545_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

/*
    *
    *  *  Copyright 2014 Orient Technologies LTD (info(at)orientechnologies.com)
    *  *
    *  *  Licensed under the Apache License, Version 2.0 (the "License");
    *  *  you may not use this file except in compliance with the License.
    *  *  You may obtain a copy of the License at
    *  *
    *  *       http://www.apache.org/licenses/LICENSE-2.0
    *  *
    *  *  Unless required by applicable law or agreed to in writing, software
    *  *  distributed under the License is distributed on an "AS IS" BASIS,
    *  *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    *  *  See the License for the specific language governing permissions and
    *  *  limitations under the License.
    *  *
    *  * For more information: http://www.orientechnologies.com
    *
    */
package com.orientechnologies.orient.server.network.protocol.http;

import com.orientechnologies.common.concur.resource.OSharedResourceAbstract;
 import com.orientechnologies.common.log.OLogManager;
 import com.orientechnologies.orient.core.Orient;
 import com.orientechnologies.orient.core.config.OGlobalConfiguration;

 import java.util.HashMap;
 import java.util.Iterator;
 import java.util.Map;
 import java.util.Map.Entry;
 import java.util.Random;
 import java.util.TimerTask;

/**
  * Handles the HTTP sessions such as a real HTTP Server.
  *
  * @author Luca Garulli
  */
 public class OHttpSessionManager extends OSharedResourceAbstract {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,141 +1,142 @@
 /*
-    *
-    *  *  Copyright 2014 Orient Technologies LTD (info(at)orientechnologies.com)
-    *  *
-    *  *  Licensed under the Apache License, Version 2.0 (the "License");
-    *  *  you may not use this file except in compliance with the License.
-    *  *  You may obtain a copy of the License at
-    *  *
-    *  *       http://www.apache.org/licenses/LICENSE-2.0
-    *  *
-    *  *  Unless required by applicable law or agreed to in writing, software
-    *  *  distributed under the License is distributed on an "AS IS" BASIS,
-    *  *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-    *  *  See the License for the specific language governing permissions and
-    *  *  limitations under the License.
-    *  *
-    *  * For more information: http://www.orientechnologies.com
-    *
-    */
+ *
+ *  *  Copyright 2014 Orient Technologies LTD (info(at)orientechnologies.com)
+ *  *
+ *  *  Licensed under the Apache License, Version 2.0 (the "License");
+ *  *  you may not use this file except in compliance with the License.
+ *  *  You may obtain a copy of the License at
+ *  *
+ *  *       http://www.apache.org/licenses/LICENSE-2.0
+ *  *
+ *  *  Unless required by applicable law or agreed to in writing, software
+ *  *  distributed under the License is distributed on an "AS IS" BASIS,
+ *  *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ *  *  See the License for the specific language governing permissions and
+ *  *  limitations under the License.
+ *  *
+ *  * For more information: http://www.orientechnologies.com
+ *
+ */
 package com.orientechnologies.orient.server.network.protocol.http;
 
 import com.orientechnologies.common.concur.resource.OSharedResourceAbstract;
- import com.orientechnologies.common.log.OLogManager;
- import com.orientechnologies.orient.core.Orient;
- import com.orientechnologies.orient.core.config.OGlobalConfiguration;
+import com.orientechnologies.common.log.OLogManager;
+import com.orientechnologies.orient.core.Orient;
+import com.orientechnologies.orient.core.config.OGlobalConfiguration;
 
- import java.util.HashMap;
- import java.util.Iterator;
- import java.util.Map;
- import java.util.Map.Entry;
- import java.util.Random;
- import java.util.TimerTask;
+import java.security.SecureRandom;
+import java.util.HashMap;
+import java.util.Iterator;
+import java.util.Map;
+import java.util.Map.Entry;
+import java.util.Random;
+import java.util.TimerTask;
 
 /**
-  * Handles the HTTP sessions such as a real HTTP Server.
-  *
-  * @author Luca Garulli
-  */
- public class OHttpSessionManager extends OSharedResourceAbstract {
-   private static final OHttpSessionManager instance = new OHttpSessionManager();
-   private Map<String, OHttpSession>        sessions = new HashMap<String, OHttpSession>();
-   private int                              expirationTime;
-   private Random                           random   = new Random();
+ * Handles the HTTP sessions such as a real HTTP Server.
+ *
+ * @author Luca Garulli
+ */
+public class OHttpSessionManager extends OSharedResourceAbstract {
+  private static final OHttpSessionManager instance = new OHttpSessionManager();
+  private Map<String, OHttpSession>        sessions = new HashMap<String, OHttpSession>();
+  private int                              expirationTime;
+  private Random                           random   = new SecureRandom();
 
-   protected OHttpSessionManager() {
-     expirationTime = OGlobalConfiguration.NETWORK_HTTP_SESSION_EXPIRE_TIMEOUT.getValueAsInteger() * 1000;
+  protected OHttpSessionManager() {
+    expirationTime = OGlobalConfiguration.NETWORK_HTTP_SESSION_EXPIRE_TIMEOUT.getValueAsInteger() * 1000;
 
-     Orient.instance().scheduleTask(new TimerTask() {
-       @Override
-       public void run() {
-         final int expired = checkSessionsValidity();
-         if (expired > 0)
-           OLogManager.instance().debug(this, "Removed %d session because expired", expired);
-       }
-     }, expirationTime, expirationTime);
-   }
+    Orient.instance().scheduleTask(new TimerTask() {
+      @Override
+      public void run() {
+        final int expired = checkSessionsValidity();
+        if (expired > 0)
+          OLogManager.instance().debug(this, "Removed %d session because expired", expired);
+      }
+    }, expirationTime, expirationTime);
+  }
 
-   public int checkSessionsValidity() {
-     int expired = 0;
+  public int checkSessionsValidity() {
+    int expired = 0;
 
-     acquireExclusiveLock();
-     try {
-       final long now = System.currentTimeMillis();
+    acquireExclusiveLock();
+    try {
+      final long now = System.currentTimeMillis();
 
-       Entry<String, OHttpSession> s;
-       for (Iterator<Map.Entry<String, OHttpSession>> it = sessions.entrySet().iterator(); it.hasNext();) {
-         s = it.next();
+      Entry<String, OHttpSession> s;
+      for (Iterator<Map.Entry<String, OHttpSession>> it = sessions.entrySet().iterator(); it.hasNext();) {
+        s = it.next();
 
-         if (now - s.getValue().getUpdatedOn() > expirationTime) {
-           // REMOVE THE SESSION
-           it.remove();
-           expired++;
-         }
-       }
+        if (now - s.getValue().getUpdatedOn() > expirationTime) {
+          // REMOVE THE SESSION
+          it.remove();
+          expired++;
+        }
+      }
 
-     } finally {
-       releaseExclusiveLock();
-     }
+    } finally {
+      releaseExclusiveLock();
+    }
 
-     return expired;
-   }
+    return expired;
+  }
 
-   public OHttpSession[] getSessions() {
-     acquireSharedLock();
-     try {
+  public OHttpSession[] getSessions() {
+    acquireSharedLock();
+    try {
 
-       return (OHttpSession[]) sessions.values().toArray(new OHttpSession[sessions.size()]);
+      return (OHttpSession[]) sessions.values().toArray(new OHttpSession[sessions.size()]);
 
-     } finally {
-       releaseSharedLock();
-     }
-   }
+    } finally {
+      releaseSharedLock();
+    }
+  }
 
-   public OHttpSession getSession(final String iId) {
-     acquireSharedLock();
-     try {
+  public OHttpSession getSession(final String iId) {
+    acquireSharedLock();
+    try {
 
-       final OHttpSession sess = sessions.get(iId);
-       if (sess != null)
-         sess.updateLastUpdatedOn();
-       return sess;
+      final OHttpSession sess = sessions.get(iId);
+      if (sess != null)
+        sess.updateLastUpdatedOn();
+      return sess;
 
-     } finally {
-       releaseSharedLock();
-     }
-   }
+    } finally {
+      releaseSharedLock();
+    }
+  }
 
-   public String createSession(final String iDatabaseName, final String iUserName, final String iUserPassword) {
-     acquireExclusiveLock();
-     try {
-       final String id = "OS" + System.currentTimeMillis() + random.nextLong();
-       sessions.put(id, new OHttpSession(id, iDatabaseName, iUserName, iUserPassword));
-       return id;
+  public String createSession(final String iDatabaseName, final String iUserName, final String iUserPassword) {
+    acquireExclusiveLock();
+    try {
+      final String id = "OS" + System.currentTimeMillis() + random.nextLong();
+      sessions.put(id, new OHttpSession(id, iDatabaseName, iUserName, iUserPassword));
+      return id;
 
-     } finally {
-       releaseExclusiveLock();
-     }
-   }
+    } finally {
+      releaseExclusiveLock();
+    }
+  }
 
-   public OHttpSession removeSession(final String iSessionId) {
-     acquireExclusiveLock();
-     try {
-       return sessions.remove(iSessionId);
+  public OHttpSession removeSession(final String iSessionId) {
+    acquireExclusiveLock();
+    try {
+      return sessions.remove(iSessionId);
 
-     } finally {
-       releaseExclusiveLock();
-     }
-   }
+    } finally {
+      releaseExclusiveLock();
+    }
+  }
 
-   public int getExpirationTime() {
-     return expirationTime;
-   }
... (diff truncated)
```
