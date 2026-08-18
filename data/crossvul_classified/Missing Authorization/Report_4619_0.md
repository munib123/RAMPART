# CrossVul Fix Pair: Missing Authorization in java
**Pair ID:** 4619_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4619_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-40 of the vulnerable file.

/*
 * Copyright (c) 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.api.client.auth.oauth2;

import com.google.api.client.auth.oauth2.Credential.AccessMethod;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.util.Beta;
import com.google.api.client.util.Clock;
import com.google.api.client.util.Joiner;
import com.google.api.client.util.Lists;
import com.google.api.client.util.Preconditions;
import com.google.api.client.util.store.DataStore;
import com.google.api.client.util.store.DataStoreFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import static com.google.api.client.util.Strings.isNullOrEmpty;

/**
 * Thread-safe OAuth 2.0 authorization code flow that manages and persists end-user credentials.
 *
 * <p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,10 +17,14 @@
 import com.google.api.client.auth.oauth2.Credential.AccessMethod;
 import com.google.api.client.http.GenericUrl;
 import com.google.api.client.http.HttpExecuteInterceptor;
+import com.google.api.client.http.HttpRequest;
 import com.google.api.client.http.HttpRequestInitializer;
 import com.google.api.client.http.HttpTransport;
+import com.google.api.client.http.UrlEncodedContent;
 import com.google.api.client.json.JsonFactory;
+import com.google.api.client.util.Base64;
 import com.google.api.client.util.Beta;
+import com.google.api.client.util.Data;
 import com.google.api.client.util.Clock;
 import com.google.api.client.util.Joiner;
 import com.google.api.client.util.Lists;
@@ -29,8 +33,12 @@
 import com.google.api.client.util.store.DataStoreFactory;
 
 import java.io.IOException;
+import java.security.MessageDigest;
+import java.security.NoSuchAlgorithmException;
+import java.security.SecureRandom;
 import java.util.Collection;
 import java.util.Collections;
+import java.util.Map;
 
 import static com.google.api.client.util.Strings.isNullOrEmpty;
 
@@ -85,6 +93,9 @@
   /** Authorization server encoded URL. */
   private final String authorizationServerEncodedUrl;
 
+  /** The Proof Key for Code Exchange (PKCE) or {@code null} if this flow should not use PKCE. */
+  private final PKCE pkce;
+
   /** Credential persistence store or {@code null} for none. */
   @Beta
   @Deprecated
@@ -159,6 +170,7 @@
     clock = Preconditions.checkNotNull(builder.clock);
     credentialCreatedListener = builder.credentialCreatedListener;
     refreshListeners = Collections.unmodifiableCollection(builder.refreshListeners);
+    pkce = builder.pkce;
   }
 
   /**
@@ -182,8 +194,13 @@
    * </pre>
    */
   public AuthorizationCodeRequestUrl newAuthorizationUrl() {
-    return new AuthorizationCodeRequestUrl(authorizationServerEncodedUrl, clientId).setScopes(
-        scopes);
+    AuthorizationCodeRequestUrl url = new  AuthorizationCodeRequestUrl(authorizationServerEncodedUrl, clientId);
+    url.setScopes(scopes);
+    if (pkce != null) {
+      url.setCodeChallenge(pkce.getChallenge());
+      url.setCodeChallengeMethod(pkce.getChallengeMethod());
+    }
+    return url;
   }
 
   /**
@@ -206,9 +223,20 @@
    * @param authorizationCode authorization code.
    */
   public AuthorizationCodeTokenRequest newTokenRequest(String authorizationCode) {
+    HttpExecuteInterceptor pkceClientAuthenticationWrapper = new HttpExecuteInterceptor() {
+      @Override
+      public void intercept(HttpRequest request) throws IOException {
+        clientAuthentication.intercept(request);
+        if (pkce != null) {
+          Map<String, Object> data = Data.mapOf(UrlEncodedContent.getContent(request).getData());
+          data.put("code_verifier", pkce.getVerifier());
+        }
+      }
+    };
+
     return new AuthorizationCodeTokenRequest(transport, jsonFactory,
         new GenericUrl(tokenServerEncodedUrl), authorizationCode).setClientAuthentication(
-        clientAuthentication).setRequestInitializer(requestInitializer).setScopes(scopes);
+        pkceClientAuthenticationWrapper).setRequestInitializer(requestInitializer).setScopes(scopes);
   }
 
   /**
@@ -413,6 +441,61 @@
   }
 
   /**
+   * An implementation of <a href="https://tools.ietf.org/html/rfc7636">Proof Key for Code Exchange</a>
+   * which, according to the <a href="https://tools.ietf.org/html/rfc8252#section-6">OAuth 2.0 for Native Apps RFC</a>,
+   * is mandatory for public native apps.
+   */
+  private static class PKCE {
+    private final String verifier;
+    private String challenge;
+    private String challengeMethod;
+
+    public PKCE() {
+      verifier = generateVerifier();
+      generateChallenge(verifier);
+    }
+
+    private static String generateVerifier() {
+      SecureRandom sr = new SecureRandom();
+      byte[] code = new byte[32];
+      sr.nextBytes(code);
+      return Base64.encodeBase64URLSafeString(code);
+    }
+
+    /**
+     * Create the PKCE code verifier. It uses the S256 method but
+     * falls back to using the 'plain' method in the unlikely case
+     * that the SHA-256 MessageDigest algorithm implementation can't be
+     * loaded.
+     */
+    private void generateChallenge(String verifier) {
+      try {
+        byte[] bytes = verifier.getBytes();
+        MessageDigest md = MessageDigest.getInstance("SHA-256");
+        md.update(bytes, 0, bytes.length);
+        byte[] digest = md.digest();
+        challenge = Base64.encodeBase64URLSafeString(digest);
+        challengeMethod = "S256";
+      } catch (NoSuchAlgorithmException e) {
+        challenge = verifier;
+        challengeMethod = "plain";
+      }
+    }
+
+    public String getVerifier() {
+      return verifier;
+    }
+
+    public String getChallenge() {
+      return challenge;
+    }
+
+    public String getChallengeMethod() {
+      return challengeMethod;
+    }
+  }
+
+  /**
    * Authorization code flow builder.
    *
    * <p>
@@ -447,6 +530,8 @@
 
     /** Authorization server encoded URL. */
     String authorizationServerEncodedUrl;
+
+    PKCE pkce;
 
     /** Credential persistence store or {@code null} for none. */
     @Deprecated
@@ -785,6 +870,16 @@
     }
 
     /**
+     * Enables Proof Key for Code Exchange (PKCE) for this Athorization Code Flow.
+     * @since 1.31
+     */
+    @Beta
+    public Builder enablePKCE() {
+      this.pkce = new PKCE();
+      return this;
+    }
+
+    /**
      * Sets the collection of scopes.
      *
      * <p>
```
