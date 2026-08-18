# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3079_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3079_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 496-536 of the vulnerable file.

        this.host.send(
                Operation.createGet(UriUtils.buildUri(this.host, ExampleService.FACTORY_LINK))
                .setCompletion((o, e) -> {
                    if (e != null) {
                        this.host.failIteration(new IllegalStateException(e));
                        return;
                    }
                    ServiceDocumentQueryResult res = o
                            .getBody(ServiceDocumentQueryResult.class);
                    if (!res.documentLinks.isEmpty()) {
                        String message = String.format("Expected 0 results; Got %d",
                                res.documentLinks.size());
                        this.host.failIteration(new IllegalStateException(message));
                        return;
                    }

                    this.host.completeIteration();
                }));
        this.host.testWait();

        // Assume Jane's identity
        this.host.assumeIdentity(this.userServicePath);
        // add docs accessible by jane
        exampleServices.putAll(createExampleServices("jane"));

        verifyJaneAccess(exampleServices, null);

        // Execute get on factory trying to get all example services
        final ServiceDocumentQueryResult[] factoryGetResult = new ServiceDocumentQueryResult[1];
        Operation getFactory = Operation.createGet(
                UriUtils.buildUri(this.host, ExampleService.FACTORY_LINK))
                .setCompletion((o, e) -> {
                    if (e != null) {
                        this.host.failIteration(e);
                        return;
                    }

                    factoryGetResult[0] = o.getBody(ServiceDocumentQueryResult.class);
                    this.host.completeIteration();
                });

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -513,6 +513,16 @@
                 }));
         this.host.testWait();
 
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
@@ -555,8 +565,26 @@
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
     }
```
