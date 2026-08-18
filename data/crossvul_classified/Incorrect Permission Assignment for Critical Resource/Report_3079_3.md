# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3079_3
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3079_3`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 282-322 of the vulnerable file.

            hostWithAuth.resetSystemAuthorizationContext();
            hostWithAuth.assumeIdentity(UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS, testUserEmail));
            MinimalTestService s = new MinimalTestService();
            MinimalTestServiceState serviceState = new MinimalTestServiceState();
            serviceState.id = UUID.randomUUID().toString();
            String minimalServiceUUID = UUID.randomUUID().toString();
            TestContext notifyContext = new TestContext(1, Duration.ofSeconds(5));
            hostWithAuth.startServiceAndWait(s, minimalServiceUUID, serviceState);

            Consumer<Operation> notifyC = (nOp) -> {
                nOp.complete();
                switch (nOp.getAction()) {
                case PUT:
                    notifyContext.completeIteration();
                    break;
                default:
                    break;

                }
            };
            Operation subscribe = Operation.createPost(UriUtils.buildUri(hostWithAuth, minimalServiceUUID));
            subscribe.setReferer(hostWithAuth.getReferer());
            ServiceSubscriber subscriber = new ServiceSubscriber();
            subscriber.replayState = true;
            hostWithAuth.startSubscriptionService(subscribe, notifyC, subscriber);
            hostWithAuth.testWait(notifyContext);
        } finally {
            if (hostWithAuth != null) {
                hostWithAuth.tearDown();
            }
        }
    }

    @Test
    public void subscribeAndWaitForServiceAvailability() throws Throwable {
        // until HTTP2 support is we must only subscribe to less than max connections!
        // otherwise we deadlock: the connection for the queued subscribe is used up,
        // no more connections can be created, to that owner.
        this.serviceCount = NettyHttpServiceClient.DEFAULT_CONNECTIONS_PER_HOST / 2;
        // set the connection limit higher for the test host since it will be issuing parallel
        // subscribes, POSTs
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -299,11 +299,14 @@
 
                 }
             };
+
+            hostWithAuth.setSystemAuthorizationContext();
             Operation subscribe = Operation.createPost(UriUtils.buildUri(hostWithAuth, minimalServiceUUID));
             subscribe.setReferer(hostWithAuth.getReferer());
             ServiceSubscriber subscriber = new ServiceSubscriber();
             subscriber.replayState = true;
             hostWithAuth.startSubscriptionService(subscribe, notifyC, subscriber);
+            hostWithAuth.resetAuthorizationContext();
             hostWithAuth.testWait(notifyContext);
         } finally {
             if (hostWithAuth != null) {
```
