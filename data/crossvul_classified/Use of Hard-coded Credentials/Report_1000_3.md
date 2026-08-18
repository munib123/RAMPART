# CrossVul Fix Pair: Use of Hard-coded Credentials in java
**Pair ID:** 1000_3
**Vulnerability Class:** Use of Hard-coded Credentials
**CWE:** CWE-798
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1000_3`)

## Vulnerability Information & PoC

## Description
Use of Hard-coded Credentials - Hard-coded credentials typically create a significant hole that allows an attacker to bypass the authentication that has been configured by the product administrator.

## Vulnerable Code
```java
Lines 214-254 of the vulnerable file.

        assertClient(client, storedClient);

        newClient.setSecret("new-secret");

        realm.clients().get(client.getId()).update(newClient);

        assertAdminEvents.assertEvent(realmId, OperationType.UPDATE, AdminEventPaths.clientResourcePath(client.getId()), newClient, ResourceType.CLIENT);

        storedClient = realm.clients().get(client.getId()).toRepresentation();
        assertClient(client, storedClient);
    }

    @Test
    public void serviceAccount() {
        Response response = realm.clients().create(ClientBuilder.create().clientId("serviceClient").serviceAccount().build());
        String id = ApiUtil.getCreatedId(response);
        getCleanup().addClientUuid(id);
        response.close();
        UserRepresentation userRep = realm.clients().get(id).getServiceAccountUser();
        assertEquals("service-account-serviceclient", userRep.getUsername());
    }

    // KEYCLOAK-3421
    @Test
    public void createClientWithFragments() {
        ClientRepresentation client = ClientBuilder.create()
                .clientId("client-with-fragment")
                .rootUrl("http://localhost/base#someFragment")
                .redirectUris("http://localhost/auth", "http://localhost/auth#fragment", "http://localhost/auth*", "/relative")
                .build();

        Response response = realm.clients().create(client);
        assertUriFragmentError(response);
    }

    // KEYCLOAK-3421
    @Test
    public void updateClientWithFragments() {
        ClientRepresentation client = ClientBuilder.create()
                .clientId("client-with-fragment")
                .redirectUris("http://localhost/auth", "http://localhost/auth*")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -231,6 +231,8 @@
         response.close();
         UserRepresentation userRep = realm.clients().get(id).getServiceAccountUser();
         assertEquals("service-account-serviceclient", userRep.getUsername());
+        // KEYCLOAK-11197 service accounts are no longer created with a placeholder e-mail.
+        assertNull(userRep.getEmail());
     }
 
     // KEYCLOAK-3421
```
