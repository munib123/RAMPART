# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3076_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3076_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 445-485 of the vulnerable file.


        // Make sure only the authorized services were returned
        ServiceDocumentQueryResult getResult = responseOp.getBody(ServiceDocumentQueryResult.class);
        assertAuthorizedServicesInResult("guest", exampleServices, getResult);
        String guestLink = getResult.documentLinks.iterator().next();

        // Make sure we are able to PATCH the example service.
        ExampleServiceState state = new ExampleServiceState();
        state.counter = 2L;
        responseOp = sender.sendAndWait(Operation.createPatch(this.host, guestLink).setBody(state));
        assertEquals(Operation.STATUS_CODE_OK, responseOp.getStatusCode());

        // Let's try to do another PATCH using kryo-octet-stream
        state.counter = 3L;
        FailureResponse failureResponse = sender.sendAndWaitFailure(
                Operation.createPatch(this.host, guestLink)
                        .setContentType(Operation.MEDIA_TYPE_APPLICATION_KRYO_OCTET_STREAM)
                        .setBody(state));
        assertEquals(Operation.STATUS_CODE_UNAUTHORIZED, failureResponse.op.getStatusCode());

        Map<String, ServiceStats.ServiceStat> stat = this.host.getServiceStats(
                UriUtils.buildUri(this.host, ServiceUriPaths.CORE_MANAGEMENT));
        double currentInsertCount = stat.get(
                ServiceHostManagementService.STAT_NAME_AUTHORIZATION_CACHE_INSERT_COUNT).latestValue;

        // Make a second request and verify that the cache did not get updated, instead Xenon re-used
        // the cached Guest authorization context.
        sender.sendAndWait(Operation.createGet(this.host, ExampleService.FACTORY_LINK));
        stat = this.host.getServiceStats(
                UriUtils.buildUri(this.host, ServiceUriPaths.CORE_MANAGEMENT));
        double newInsertCount = stat.get(
                ServiceHostManagementService.STAT_NAME_AUTHORIZATION_CACHE_INSERT_COUNT).latestValue;
        assertTrue(currentInsertCount == newInsertCount);

        // Make sure that Authorization Context cache in Xenon has at least one cached token.
        double currentCacheSize = stat.get(
                ServiceHostManagementService.STAT_NAME_AUTHORIZATION_CACHE_SIZE).latestValue;
        assertTrue(currentCacheSize == newInsertCount);
    }

    @Test
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -462,16 +462,20 @@
                         .setBody(state));
         assertEquals(Operation.STATUS_CODE_UNAUTHORIZED, failureResponse.op.getStatusCode());
 
+        OperationContext.setAuthorizationContext(this.host.getSystemAuthorizationContext());
         Map<String, ServiceStats.ServiceStat> stat = this.host.getServiceStats(
                 UriUtils.buildUri(this.host, ServiceUriPaths.CORE_MANAGEMENT));
         double currentInsertCount = stat.get(
                 ServiceHostManagementService.STAT_NAME_AUTHORIZATION_CACHE_INSERT_COUNT).latestValue;
+        OperationContext.setAuthorizationContext(null);
 
         // Make a second request and verify that the cache did not get updated, instead Xenon re-used
         // the cached Guest authorization context.
         sender.sendAndWait(Operation.createGet(this.host, ExampleService.FACTORY_LINK));
+        OperationContext.setAuthorizationContext(this.host.getSystemAuthorizationContext());
         stat = this.host.getServiceStats(
                 UriUtils.buildUri(this.host, ServiceUriPaths.CORE_MANAGEMENT));
+        OperationContext.setAuthorizationContext(null);
         double newInsertCount = stat.get(
                 ServiceHostManagementService.STAT_NAME_AUTHORIZATION_CACHE_INSERT_COUNT).latestValue;
         assertTrue(currentInsertCount == newInsertCount);
@@ -709,6 +713,16 @@
                 }));
         this.host.testWait(ctx2);
 
+        // do GET on factory /stats, we should get 403
+        Operation statsGet = Operation.createGet(this.host,
+                ExampleService.FACTORY_LINK + ServiceHost.SERVICE_URI_SUFFIX_STATS);
+        this.host.sendAndWaitExpectFailure(statsGet, Operation.STATUS_CODE_FORBIDDEN);
+
+        // do GET on factory /config, we should get 403
+        Operation configGet = Operation.createGet(this.host,
+                ExampleService.FACTORY_LINK + ServiceHost.SERVICE_URI_SUFFIX_CONFIG);
+        this.host.sendAndWaitExpectFailure(configGet, Operation.STATUS_CODE_FORBIDDEN);
+
         // Assume Jane's identity
         this.host.assumeIdentity(this.userServicePath);
         // add docs accessible by jane
@@ -750,8 +764,26 @@
         // reset the auth context
         OperationContext.setAuthorizationContext(null);
 
+        // do GET on utility suffixes in example child services, we should get 403
+        for (URI childUri : exampleServices.keySet()) {
+            statsGet = Operation.createGet(this.host,
+                    childUri.getPath() + ServiceHost.SERVICE_URI_SUFFIX_STATS);
+            this.host.sendAndWaitExpectFailure(statsGet, Operation.STATUS_CODE_FORBIDDEN);
+            configGet = Operation.createGet(this.host,
+                    childUri.getPath() + ServiceHost.SERVICE_URI_SUFFIX_CONFIG);
+            this.host.sendAndWaitExpectFailure(configGet, Operation.STATUS_CODE_FORBIDDEN);
+        }
+
         // Assume Jane's identity through header auth token
         String authToken = generateAuthToken(this.userServicePath);
+
+        // do GET on utility suffixes in example child services, we should get 200
+        for (URI childUri : exampleServices.keySet()) {
+            statsGet = Operation.createGet(this.host,
+                    childUri.getPath() + ServiceHost.SERVICE_URI_SUFFIX_STATS);
+            statsGet.addRequestHeader(Operation.REQUEST_AUTH_TOKEN_HEADER, authToken);
+            this.host.sendAndWaitExpectSuccess(statsGet);
+        }
 
         verifyJaneAccess(exampleServices, authToken);
 
```
