# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3078_2
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3078_2`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 64-107 of the vulnerable file.


            h.initialize(args);
            h.setMaintenanceIntervalMicros(TimeUnit.MILLISECONDS.toMicros(100));
            h.start();

            URI hostUri = h.getUri();
            String authToken = loginUser(hostUri);
            waitForUsers(hostUri, authToken);

        } finally {
            h.stop();
            tmpFolder.delete();
        }
    }

    /**
     * Supports createUsers() by logging in as the admin. The admin user
     * isn't created immediately, so this polls.
     */
    private String loginUser(URI hostUri) throws Throwable {
        URI usersLink = UriUtils.buildUri(hostUri, UserService.FACTORY_LINK);
        // wait for factory availability
        this.host.waitForReplicatedFactoryServiceAvailable(usersLink);

        String basicAuth = BasicAuthenticationUtils.constructBasicAuth(adminUser, adminUser);
        URI loginUri = UriUtils.buildUri(hostUri, ServiceUriPaths.CORE_AUTHN_BASIC);
        AuthenticationRequest login = new AuthenticationRequest();
        login.requestType = AuthenticationRequest.AuthenticationRequestType.LOGIN;

        String[] authToken = new String[1];
        authToken[0] = null;

        Date exp = this.host.getTestExpiration();
        while (new Date().before(exp)) {
            Operation loginPost = Operation.createPost(loginUri)
                    .setBody(login)
                    .addRequestHeader(Operation.AUTHORIZATION_HEADER, basicAuth)
                    .forceRemote()
                    .setCompletion((op, ex) -> {
                        if (ex != null) {
                            this.host.completeIteration();
                            return;
                        }
                        authToken[0] = op.getResponseHeader(Operation.REQUEST_AUTH_TOKEN_HEADER);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,10 +81,6 @@
      * isn't created immediately, so this polls.
      */
     private String loginUser(URI hostUri) throws Throwable {
-        URI usersLink = UriUtils.buildUri(hostUri, UserService.FACTORY_LINK);
-        // wait for factory availability
-        this.host.waitForReplicatedFactoryServiceAvailable(usersLink);
-
         String basicAuth = BasicAuthenticationUtils.constructBasicAuth(adminUser, adminUser);
         URI loginUri = UriUtils.buildUri(hostUri, ServiceUriPaths.CORE_AUTHN_BASIC);
         AuthenticationRequest login = new AuthenticationRequest();
```
