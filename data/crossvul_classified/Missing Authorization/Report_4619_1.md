# CrossVul Fix Pair: Missing Authorization in java
**Pair ID:** 4619_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4619_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 1-36 of the vulnerable file.

/*
 * Copyright (c) 2011 Google Inc.
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

import java.util.Collection;
import java.util.Collections;

/**
 * OAuth 2.0 URL builder for an authorization web page to allow the end user to authorize the
 * application to access their protected resources and that returns an authorization code, as
 * specified in <a href="http://tools.ietf.org/html/rfc6749#section-4.1">Authorization Code
 * Grant</a>.
 *
 * <p>
 * The default for {@link #getResponseTypes()} is {@code "code"}. Use
 * {@link AuthorizationCodeResponseUrl} to parse the redirect response after the end user
 * grants/denies the request. Using the authorization code in this response, use
 * {@link AuthorizationCodeTokenRequest} to request the access token.
 * </p>
 *
 * <p>
 * Sample usage for a web application:
 * </p>
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,8 @@
  */
 
 package com.google.api.client.auth.oauth2;
+
+import com.google.api.client.util.Key;
 
 import java.util.Collection;
 import java.util.Collections;
@@ -53,11 +55,63 @@
 public class AuthorizationCodeRequestUrl extends AuthorizationRequestUrl {
 
   /**
+   * The PKCE <a href="https://tools.ietf.org/html/rfc7636#section-4.3">Code Challenge</a>.
+   * @since 1.31
+   */
+  @Key("code_challenge")
+  String codeChallenge;
+
+  /**
+   * The PKCE <a href="https://tools.ietf.org/html/rfc7636#section-4.3">Code Challenge Method</a>.
+   * @since 1.31
+   */
+  @Key("code_challenge_method")
+  String codeChallengeMethod;
+
+  /**
    * @param authorizationServerEncodedUrl authorization server encoded URL
    * @param clientId client identifier
    */
   public AuthorizationCodeRequestUrl(String authorizationServerEncodedUrl, String clientId) {
     super(authorizationServerEncodedUrl, clientId, Collections.singleton("code"));
+  }
+
+  /**
+   * Get the code challenge (<a href="https://tools.ietf.org/html/rfc7636#section-4.3">details</a>).
+   *
+   * @since 1.31
+   */
+  public String getCodeChallenge() {
+    return codeChallenge;
+  }
+
+  /**
+   * Get the code challenge method (<a href="https://tools.ietf.org/html/rfc7636#section-4.3">details</a>).
+   *
+   * @since 1.31
+   */
+  public String getCodeChallengeMethod() {
+    return codeChallengeMethod;
+  }
+
+  /**
+   * Set the code challenge (<a href="https://tools.ietf.org/html/rfc7636#section-4.3">details</a>).
+   * @param codeChallenge the code challenge.
+   *
+   * @since 1.31
+   */
+  public void setCodeChallenge(String codeChallenge) {
+    this.codeChallenge = codeChallenge;
+  }
+
+  /**
+   * Set the code challenge method (<a href="https://tools.ietf.org/html/rfc7636#section-4.3">details</a>).
+   * @param codeChallengeMethod the code challenge method.
+   *
+   * @since 1.31
+   */
+  public void setCodeChallengeMethod(String codeChallengeMethod) {
+    this.codeChallengeMethod = codeChallengeMethod;
   }
 
   @Override
```
