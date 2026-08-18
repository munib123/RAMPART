# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1737_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1737_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 33-73 of the vulnerable file.

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Lee YOU
 */
public class OAuth2Helper {

	private static final Logger log = LoggerFactory.getLogger(OAuth2Helper.class);

	public static URL getOAuth2URL(OAuth2Provider provider) {
		log.trace("getOAuth2URL {}", provider);

		String oAuth2Location = provider.getAuthLocation();
		String oAuth2ClientId = provider.getClientId();
		String scopes = Utils.toCsv(provider.getPermissionScopes());
		try {
			OAuthClientRequest oAuthRequest = OAuthClientRequest
					.authorizationLocation(oAuth2Location)
					.setClientId(oAuth2ClientId)
					.setResponseType("code")
					.setScope(scopes)
					.setState(provider.getProviderId())
					.setRedirectURI(provider.getRedirectURI())
					.buildQueryMessage();

			return new URL(oAuthRequest.getLocationUri());
		} catch (OAuthSystemException oAuthSystemException) {
			throw new RuntimeException(oAuthSystemException);
		} catch (MalformedURLException malformedURLException) {
			throw new RuntimeException(malformedURLException);
		}

	}

	private final NonceProvider nonceProvider;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,7 @@
 
 		String oAuth2Location = provider.getAuthLocation();
 		String oAuth2ClientId = provider.getClientId();
-		String scopes = Utils.toCsv(provider.getPermissionScopes());
+		String scopes = Utils.toCsv(provider.getPermissionScopes(), false);
 		try {
 			OAuthClientRequest oAuthRequest = OAuthClientRequest
 					.authorizationLocation(oAuth2Location)
```
