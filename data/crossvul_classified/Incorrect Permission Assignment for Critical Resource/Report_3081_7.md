# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3081_7
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3081_7`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 63-103 of the vulnerable file.


import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.apache.lucene.store.LockObtainFailedException;
import org.junit.rules.TemporaryFolder;

import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.CommandLineArgumentParser;
import com.vmware.xenon.common.DeferredResult;
import com.vmware.xenon.common.NodeSelectorService;
import com.vmware.xenon.common.NodeSelectorState;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Operation.AuthorizationContext;
import com.vmware.xenon.common.Operation.CompletionHandler;
import com.vmware.xenon.common.Service;
import com.vmware.xenon.common.Service.Action;
import com.vmware.xenon.common.Service.ServiceOption;
import com.vmware.xenon.common.ServiceClient;
import com.vmware.xenon.common.ServiceConfigUpdateRequest;
import com.vmware.xenon.common.ServiceConfiguration;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.ServiceDocumentDescription;
import com.vmware.xenon.common.ServiceDocumentDescription.Builder;
import com.vmware.xenon.common.ServiceDocumentQueryResult;
import com.vmware.xenon.common.ServiceErrorResponse;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.ServiceStats;
import com.vmware.xenon.common.ServiceStats.ServiceStat;
import com.vmware.xenon.common.ServiceStats.ServiceStatLogHistogram;
import com.vmware.xenon.common.TaskState;
import com.vmware.xenon.common.TestResults;
import com.vmware.xenon.common.UriUtils;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.common.http.netty.NettyChannelContext;
import com.vmware.xenon.common.http.netty.NettyHttpServiceClient;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,7 @@
 import com.vmware.xenon.common.Operation;
 import com.vmware.xenon.common.Operation.AuthorizationContext;
 import com.vmware.xenon.common.Operation.CompletionHandler;
+import com.vmware.xenon.common.OperationContext;
 import com.vmware.xenon.common.Service;
 import com.vmware.xenon.common.Service.Action;
 import com.vmware.xenon.common.Service.ServiceOption;
@@ -1049,7 +1050,15 @@
     }
 
     public Map<String, ServiceStat> getServiceStats(URI serviceUri) {
+        AuthorizationContext ctx = null;
+        if (this.isAuthorizationEnabled()) {
+            ctx = OperationContext.getAuthorizationContext();
+            this.setSystemAuthorizationContext();
+        }
         ServiceStats stats = this.sender.sendStatsGetAndWait(serviceUri);
+        if (this.isAuthorizationEnabled()) {
+            this.setAuthorizationContext(ctx);
+        }
         return stats.entries;
     }
 
```
