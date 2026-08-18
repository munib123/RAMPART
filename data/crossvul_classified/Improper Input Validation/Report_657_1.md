# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 657_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `657_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 406-446 of the vulnerable file.

        InputStream is = this.getClass().getClassLoader().getResource("entity_wreq.xml").openStream();
        String entity = IOUtils.toString(is, "UTF-8");
        is.close();
        String validWreq =
            "<RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
            + "<TokenType>&m;http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</TokenType>"
            + "</RequestSecurityToken>";

        url += "&wreq=" + URLEncoder.encode(entity + validWreq, "UTF-8");

        String user = "alice";
        String password = "ecila";

        final WebClient webClient = new WebClient();
        webClient.getOptions().setUseInsecureSSL(true);
        webClient.getCredentialsProvider().setCredentials(
            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
            new UsernamePasswordCredentials(user, password));

        webClient.getOptions().setJavaScriptEnabled(false);
        try {
            webClient.getPage(url);
            Assert.fail("Failure expected on a bad wreq value");
        } catch (FailingHttpStatusCodeException ex) {
            Assert.assertEquals(ex.getStatusCode(), 400);
        }

        webClient.close();
    }

    // Send an malformed wreq value
    @org.junit.Test
    public void testMalformedWReq() throws Exception {
        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?";
        url += "wa=wsignin1.0";
        url += "&whr=urn:org:apache:cxf:fediz:idp:realm-A";
        url += "&wtrealm=urn:org:apache:cxf:fediz:fedizhelloworld";
        String wreply = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
        url += "&wreply=" + wreply;

        String testWReq =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,6 +433,47 @@
         webClient.close();
     }
 
+    // Send an entity expansion attack for the wreq value
+    @org.junit.Test
+    public void testEntityExpansionWReq2() throws Exception {
+        String url = "https://localhost:" + getIdpHttpsPort() + "/fediz-idp/federation?";
+        url += "wa=wsignin1.0";
+        url += "&whr=urn:org:apache:cxf:fediz:idp:realm-A";
+        url += "&wtrealm=urn:org:apache:cxf:fediz:fedizhelloworld";
+        String wreply = "https://localhost:" + getRpHttpsPort() + "/" + getServletContextName() + "/secure/fedservlet";
+        url += "&wreply=" + wreply;
+
+        InputStream is = this.getClass().getClassLoader().getResource("entity_wreq2.xml").openStream();
+        String entity = IOUtils.toString(is, "UTF-8");
+        is.close();
+        String validWreq =
+            "<RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
+            + "<TokenType>&m;http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</TokenType>"
+            + "</RequestSecurityToken>";
+
+        url += "&wreq=" + URLEncoder.encode(entity + validWreq, "UTF-8");
+
+        String user = "alice";
+        String password = "ecila";
+
+        final WebClient webClient = new WebClient();
+        webClient.getOptions().setUseInsecureSSL(true);
+        webClient.getCredentialsProvider().setCredentials(
+            new AuthScope("localhost", Integer.parseInt(getIdpHttpsPort())),
+            new UsernamePasswordCredentials(user, password));
+
+        webClient.getOptions().setJavaScriptEnabled(false);
+
+        try {
+            webClient.getPage(url);
+            Assert.fail("Failure expected on a bad wreq value");
+        } catch (FailingHttpStatusCodeException ex) {
+            Assert.assertEquals(ex.getStatusCode(), 400);
+        }
+
+        webClient.close();
+    }
+
     // Send an malformed wreq value
     @org.junit.Test
     public void testMalformedWReq() throws Exception {
```
