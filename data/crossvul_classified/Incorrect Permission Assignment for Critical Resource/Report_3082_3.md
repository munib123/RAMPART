# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3082_3
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3082_3`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 405-445 of the vulnerable file.

            for (int i = 0; i < count; i++) {
                Operation op = Operation.createPatch(serviceUri)
                        .setBody(patchBody)
                        .forceRemote()
                        .setCompletion(c);
                this.host.send(op);
            }
        }
        this.host.testWait(ctx);
        ctx.logAfter();

        assertTrue(failureCount.get() > 0);

        // now change the options, and instead of fail, request throttling. this will literally
        // throttle the HTTP listener (does not work on local, in process calls)

        ri = new RequestRateInfo();
        ri.limit = limit;
        ri.options = EnumSet.of(RequestRateInfo.Option.PAUSE_PROCESSING);
        this.host.setRequestRateLimit(userPath, ri);
        this.host.assumeIdentity(userPath);

        ServiceStat rateLimitStatBefore = getRateLimitOpCountStat();
        if (rateLimitStatBefore == null) {
            rateLimitStatBefore = new ServiceStat();
            rateLimitStatBefore.latestValue = 0.0;
        }
        TestContext ctx2 = this.host.testCreate(count * states.size());
        ctx2.setTestName("Rate limiting with auto-read pause of channels").logBefore();
        for (URI serviceUri : states.keySet()) {
            for (int i = 0; i < count; i++) {
                // expect zero failures, but rate limit applied stat should have hits
                Operation op = Operation.createPatch(serviceUri)
                        .setBody(patchBody)
                        .forceRemote()
                        .setCompletion(ctx2.getCompletion());
                this.host.send(op);
            }
        }
        this.host.testWait(ctx2);
        ctx2.logAfter();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -422,9 +422,13 @@
         ri.limit = limit;
         ri.options = EnumSet.of(RequestRateInfo.Option.PAUSE_PROCESSING);
         this.host.setRequestRateLimit(userPath, ri);
+
+        this.host.setSystemAuthorizationContext();
+        ServiceStat rateLimitStatBefore = getRateLimitOpCountStat();
+        this.host.resetSystemAuthorizationContext();
+
         this.host.assumeIdentity(userPath);
 
-        ServiceStat rateLimitStatBefore = getRateLimitOpCountStat();
         if (rateLimitStatBefore == null) {
             rateLimitStatBefore = new ServiceStat();
             rateLimitStatBefore.latestValue = 0.0;
@@ -443,7 +447,10 @@
         }
         this.host.testWait(ctx2);
         ctx2.logAfter();
+
+        this.host.setSystemAuthorizationContext();
         ServiceStat rateLimitStatAfter = getRateLimitOpCountStat();
+        this.host.resetSystemAuthorizationContext();
         assertTrue(rateLimitStatAfter.latestValue > rateLimitStatBefore.latestValue);
 
         this.host.setMaintenanceIntervalMicros(
@@ -473,7 +480,9 @@
         ctx3.logAfter();
 
         // verify rate limiting did not happen
+        this.host.setSystemAuthorizationContext();
         ServiceStat rateLimitStatExpectSame = getRateLimitOpCountStat();
+        this.host.resetSystemAuthorizationContext();
         assertTrue(rateLimitStatAfter.latestValue == rateLimitStatExpectSame.latestValue);
     }
 
@@ -2225,8 +2234,9 @@
 
     private ServiceStat getRateLimitOpCountStat() throws Throwable {
         URI managementServiceUri = this.host.getManagementServiceUri();
-        return this.host.getServiceStats(managementServiceUri)
+        ServiceStat stats = this.host.getServiceStats(managementServiceUri)
                 .get(ServiceHostManagementService.STAT_NAME_RATE_LIMITED_OP_COUNT);
+        return stats;
     }
 
     @Test
```
