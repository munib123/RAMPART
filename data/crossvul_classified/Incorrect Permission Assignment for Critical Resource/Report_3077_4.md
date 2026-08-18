# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3077_4
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3077_4`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 283-323 of the vulnerable file.

            hostWithAuth.resetSystemAuthorizationContext();
            hostWithAuth.assumeIdentity(UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS, testUserEmail));
            MinimalTestService s = new MinimalTestService();
            MinimalTestServiceState serviceState = new MinimalTestServiceState();
            serviceState.id = UUID.randomUUID().toString();
            String minimalServiceUUID = UUID.randomUUID().toString();
            TestContext notifyContext = hostWithAuth.testCreate(1);
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
    public void testSubscriptionsWithExpiry() throws Throwable {
        MinimalTestService s = new MinimalTestService();
        MinimalTestServiceState serviceState = new MinimalTestServiceState();
        serviceState.id = UUID.randomUUID().toString();
        String minimalServiceUUID = UUID.randomUUID().toString();
        TestContext notifyContext = this.host.testCreate(1);
        TestContext notifyDeleteContext = this.host.testCreate(1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -300,11 +300,14 @@
 
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
