# CrossVul Fix Pair: Missing Authorization in java
**Pair ID:** 4619_2
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4619_2`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 6-46 of the vulnerable file.

 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.api.client.auth.oauth2;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow.CredentialCreatedListener;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Joiner;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

/**
 * Tests {@link AuthorizationCodeFlow}.
 *
 * @author Yaniv Inbar
 */
public class AuthorizationCodeFlowTest extends AuthenticationTestBase {

  static class MyCredentialCreatedListener implements CredentialCreatedListener {

    boolean called = false;

    public void onCredentialCreated(Credential credential, TokenResponse tokenResponse)
        throws IOException {
      called = true;
    }
  }

  static class MyCredentialRefreshListener implements CredentialRefreshListener {

    boolean calledOnResponse = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,8 @@
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.Collections;
+import java.util.HashSet;
+import java.util.Set;
 
 /**
  * Tests {@link AuthorizationCodeFlow}.
@@ -123,4 +125,24 @@
       assertEquals(Joiner.on(' ').join(scopes), url.getScopes());
     }
   }
+
+  public void testPKCE() {
+    AuthorizationCodeFlow flow =
+        new AuthorizationCodeFlow.Builder(BearerToken.queryParameterAccessMethod(),
+            new AccessTokenTransport(),
+            new JacksonFactory(),
+            TOKEN_SERVER_URL,
+            new BasicAuthentication(CLIENT_ID, CLIENT_SECRET),
+            CLIENT_ID,
+            "https://example.com")
+        .enablePKCE()
+        .build();
+
+    AuthorizationCodeRequestUrl url = flow.newAuthorizationUrl();
+    assertNotNull(url.getCodeChallenge());
+    assertNotNull(url.getCodeChallengeMethod());
+    Set<String> methods = new HashSet<>(Arrays.asList("plain", "s256"));
+    assertTrue(methods.contains(url.getCodeChallengeMethod().toLowerCase()));
+    assertTrue(url.getCodeChallenge().length() > 0);
+  }
 }
```
