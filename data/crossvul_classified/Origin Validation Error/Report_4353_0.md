# CrossVul Fix Pair: Origin Validation Error in java
**Pair ID:** 4353_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4353_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```java
Lines 10-53 of the vulnerable file.

 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.kernel.http.impl;

import org.opencastproject.kernel.http.api.HttpClient;

import org.apache.http.HttpResponse;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Implementation of HttpClient that makes http requests. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,28 +27,12 @@
 import org.apache.http.client.CredentialsProvider;
 import org.apache.http.client.methods.HttpUriRequest;
 import org.apache.http.conn.ClientConnectionManager;
-import org.apache.http.conn.scheme.Scheme;
-import org.apache.http.conn.scheme.SchemeRegistry;
-import org.apache.http.conn.ssl.SSLSocketFactory;
-import org.apache.http.conn.ssl.X509HostnameVerifier;
 import org.apache.http.impl.client.DefaultHttpClient;
 import org.apache.http.params.HttpParams;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;
 
 import java.io.IOException;
-import java.security.KeyManagementException;
-import java.security.NoSuchAlgorithmException;
-import java.security.SecureRandom;
-import java.security.cert.CertificateException;
-import java.security.cert.X509Certificate;
-
-import javax.net.ssl.SSLContext;
-import javax.net.ssl.SSLException;
-import javax.net.ssl.SSLSession;
-import javax.net.ssl.SSLSocket;
-import javax.net.ssl.TrustManager;
-import javax.net.ssl.X509TrustManager;
 
 /** Implementation of HttpClient that makes http requests. */
 public class HttpClientImpl implements HttpClient {
@@ -57,7 +41,7 @@
   private static final Logger logger = LoggerFactory.getLogger(HttpClientImpl.class);
 
   /** client used for all http requests. */
-  private DefaultHttpClient defaultHttpClient = makeHttpClient();
+  private DefaultHttpClient defaultHttpClient = new DefaultHttpClient();
 
   /** See org.opencastproject.kernel.http.api.HttpClient */
   @Override
@@ -83,123 +67,4 @@
     return defaultHttpClient.getConnectionManager();
   }
 
-  /**
-   * Creates a new client that can deal with all kinds of oddities with regards to http/https connections.
-   *
-   * @return the client
-   */
-  private DefaultHttpClient makeHttpClient() {
-
-    DefaultHttpClient defaultHttpClient = new DefaultHttpClient();
-    try {
-      logger.debug("Installing forgiving hostname verifier and trust managers");
-      X509TrustManager trustManager = createTrustManager();
-      X509HostnameVerifier hostNameVerifier = createHostNameVerifier();
-      SSLContext sslContext = SSLContext.getInstance("TLS");
-      sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
-      SSLSocketFactory ssf = new SSLSocketFactory(sslContext, hostNameVerifier);
-      ClientConnectionManager ccm = defaultHttpClient.getConnectionManager();
-      SchemeRegistry sr = ccm.getSchemeRegistry();
-      sr.register(new Scheme("https", 443, ssf));
-    } catch (NoSuchAlgorithmException e) {
-      logger.error("Error creating context to handle TLS connections: {}", e.getMessage());
-    } catch (KeyManagementException e) {
-      logger.error("Error creating context to handle TLS connections: {}", e.getMessage());
-    }
-
-    return defaultHttpClient;
-  }
-
-  /**
-   * Returns a new trust manager which will be in charge of checking the SSL certificates that are being presented by
-   * SSL enabled hosts.
-   *
-   * @return the trust manager
-   */
-  private X509TrustManager createTrustManager() {
-    X509TrustManager trustManager = new X509TrustManager() {
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
-       */
-      public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
-        logger.trace("Skipping trust check on client certificate {}", string);
-      }
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
-       */
-      public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
-        logger.trace("Skipping trust check on server certificate {}", string);
-      }
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
-       */
-      public X509Certificate[] getAcceptedIssuers() {
-        logger.trace("Returning empty list of accepted issuers");
-        return null;
-      }
-
-    };
-
-    return trustManager;
-  }
-
-  /**
-   * Creates a host name verifier that will make sure the SSL host's name matches the name in the SSL certificate.
-   *
-   * @return the host name verifier
-   */
-  private X509HostnameVerifier createHostNameVerifier() {
-    X509HostnameVerifier verifier = new X509HostnameVerifier() {
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, javax.net.ssl.SSLSocket)
-       */
-      public void verify(String host, SSLSocket ssl) throws IOException {
-        logger.trace("Skipping SSL host name check on {}", host);
-      }
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, java.security.cert.X509Certificate)
-       */
-      public void verify(String host, X509Certificate xc) throws SSLException {
-        logger.trace("Skipping X509 certificate host name check on {}", host);
-      }
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see org.apache.http.conn.ssl.X509HostnameVerifier#verify(java.lang.String, java.lang.String[],
-       *      java.lang.String[])
-       */
-      public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException {
-        logger.trace("Skipping DNS host name check on {}", host);
-      }
-
-      /**
-       * {@InheritDoc}
-       *
-       * @see javax.net.ssl.HostnameVerifier#verify(java.lang.String, javax.net.ssl.SSLSession)
-       */
-      public boolean verify(String host, SSLSession ssl) {
-        logger.trace("Skipping SSL session host name check on {}", host);
-        return true;
-      }
-    };
-
-    return verifier;
-  }
-
 }
```
