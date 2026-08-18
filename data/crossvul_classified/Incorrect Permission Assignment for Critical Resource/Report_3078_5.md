# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3078_5
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3078_5`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 1-37 of the vulnerable file.

/*
 * Copyright (c) 2014-2015 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, without warranties or
 * conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.vmware.xenon.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;

import com.vmware.xenon.common.Service.ServiceOption;
import com.vmware.xenon.common.ServiceStats.ServiceStat;
import com.vmware.xenon.common.ServiceStats.ServiceStatLogHistogram;
import com.vmware.xenon.common.ServiceStats.TimeSeriesStats;
import com.vmware.xenon.common.ServiceStats.TimeSeriesStats.AggregationType;
import com.vmware.xenon.common.ServiceStats.TimeSeriesStats.TimeBin;
import com.vmware.xenon.common.test.TestContext;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,11 @@
 package com.vmware.xenon.common;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertTrue;
+
+import static com.vmware.xenon.common.ServiceHost.SERVICE_URI_SUFFIX_TEMPLATE;
+import static com.vmware.xenon.common.ServiceHost.SERVICE_URI_SUFFIX_UI;
 
 import java.net.URI;
 import java.util.ArrayList;
@@ -34,10 +38,16 @@
 import com.vmware.xenon.common.ServiceStats.TimeSeriesStats;
 import com.vmware.xenon.common.ServiceStats.TimeSeriesStats.AggregationType;
 import com.vmware.xenon.common.ServiceStats.TimeSeriesStats.TimeBin;
+import com.vmware.xenon.common.test.AuthTestUtils;
 import com.vmware.xenon.common.test.TestContext;
+import com.vmware.xenon.common.test.TestRequestSender;
+import com.vmware.xenon.common.test.TestRequestSender.FailureResponse;
+import com.vmware.xenon.common.test.VerificationHost;
+import com.vmware.xenon.services.common.AuthorizationContextService;
 import com.vmware.xenon.services.common.ExampleService;
 import com.vmware.xenon.services.common.ExampleService.ExampleServiceState;
 import com.vmware.xenon.services.common.MinimalTestService;
+import com.vmware.xenon.services.common.QueryTask.Query;
 import com.vmware.xenon.services.common.ServiceUriPaths;
 
 public class TestUtilityService extends BasicReusableHostTestCase {
@@ -823,4 +833,144 @@
         assertEquals("stat index 2", "keyCCC", statList.get(2));
     }
 
+    @Test
+    public void endpointAuthorization() throws Throwable {
+        VerificationHost host = VerificationHost.create(0);
+        host.setAuthorizationService(new AuthorizationContextService());
+        host.setAuthorizationEnabled(true);
+        host.setMaintenanceIntervalMicros(TimeUnit.MILLISECONDS.toMicros(100));
+        host.start();
+
+        TestRequestSender sender = host.getTestRequestSender();
+
+        host.setSystemAuthorizationContext();
+        host.waitForReplicatedFactoryServiceAvailable(UriUtils.buildUri(host, ExampleService.FACTORY_LINK));
+
+        String exampleUser = "example@vmware.com";
+        String examplePass = "password";
+        TestContext authCtx = host.testCreate(1);
+        AuthorizationSetupHelper.create()
+                .setHost(host)
+                .setUserEmail(exampleUser)
+                .setUserPassword(examplePass)
+                .setResourceQuery(Query.Builder.create()
+                        .addFieldClause(ServiceDocument.FIELD_NAME_KIND, Utils.buildKind(ExampleServiceState.class))
+                        .build())
+                .setCompletion(authCtx.getCompletion())
+                .start();
+        authCtx.await();
+
+        // create a sample service
+        ExampleServiceState doc = new ExampleServiceState();
+        doc.name = "foo";
+        doc.documentSelfLink = "foo";
+
+        Operation post = Operation.createPost(host, ExampleService.FACTORY_LINK).setBody(doc);
+        ExampleServiceState postResult = sender.sendAndWait(post, ExampleServiceState.class);
+
+        host.resetAuthorizationContext();
+
+        URI factoryAvailableUri = UriUtils.buildAvailableUri(host, ExampleService.FACTORY_LINK);
+        URI factoryStatsUri = UriUtils.buildStatsUri(host, ExampleService.FACTORY_LINK);
+        URI factoryConfigUri = UriUtils.buildConfigUri(host, ExampleService.FACTORY_LINK);
+        URI factorySubscriptionUri = UriUtils.buildSubscriptionUri(host, ExampleService.FACTORY_LINK);
+        URI factoryTemplateUri = UriUtils.buildUri(host, UriUtils.buildUriPath(ExampleService.FACTORY_LINK, SERVICE_URI_SUFFIX_TEMPLATE));
+        URI factoryUiUri = UriUtils.buildUri(host, UriUtils.buildUriPath(ExampleService.FACTORY_LINK, SERVICE_URI_SUFFIX_UI));
+
+        URI serviceAvailableUri = UriUtils.buildAvailableUri(host, postResult.documentSelfLink);
+        URI serviceStatsUri = UriUtils.buildStatsUri(host, postResult.documentSelfLink);
+        URI serviceConfigUri = UriUtils.buildConfigUri(host, postResult.documentSelfLink);
+        URI serviceSubscriptionUri = UriUtils.buildSubscriptionUri(host, postResult.documentSelfLink);
+        URI serviceTemplateUri = UriUtils.buildUri(host, UriUtils.buildUriPath(postResult.documentSelfLink, SERVICE_URI_SUFFIX_TEMPLATE));
+        URI serviceUiUri = UriUtils.buildUri(host, UriUtils.buildUriPath(postResult.documentSelfLink, SERVICE_URI_SUFFIX_UI));
+
+        // check non-authenticated user receives forbidden response
+        FailureResponse failureResponse;
+        Operation uiOpResult;
+
+        // check factory endpoints
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(factoryAvailableUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(factoryStatsUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(factoryConfigUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(factorySubscriptionUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(factoryTemplateUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        uiOpResult = sender.sendAndWait(Operation.createGet(factoryUiUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, uiOpResult.getStatusCode());
+
+        // check service endpoints
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(serviceAvailableUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(serviceStatsUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(serviceConfigUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(serviceSubscriptionUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        failureResponse = sender.sendAndWaitFailure(Operation.createGet(serviceTemplateUri));
+        assertEquals(Operation.STATUS_CODE_FORBIDDEN, failureResponse.op.getStatusCode());
+
+        uiOpResult = sender.sendAndWait(Operation.createGet(serviceUiUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, uiOpResult.getStatusCode());
+
+
+        // check authenticated user does NOT receive forbidden response
+        AuthTestUtils.login(host, exampleUser, examplePass);
+
+        Operation response;
+
+        // check factory endpoints
+        response = sender.sendAndWait(Operation.createGet(factoryAvailableUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, response.getStatusCode());
+
+        response = sender.sendAndWait(Operation.createGet(factoryStatsUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, response.getStatusCode());
+
+        response = sender.sendAndWait(Operation.createGet(factoryConfigUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, response.getStatusCode());
+
+        response = sender.sendAndWait(Operation.createGet(factorySubscriptionUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, response.getStatusCode());
+
+        response = sender.sendAndWait(Operation.createGet(factoryTemplateUri));
+        assertNotEquals(Operation.STATUS_CODE_FORBIDDEN, response.getStatusCode());
+
+        response = sender.sendAndWait(Operation.createGet(factoryUiUri));
... (diff truncated)
```
