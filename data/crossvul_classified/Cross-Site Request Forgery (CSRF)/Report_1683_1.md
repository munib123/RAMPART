# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in c
**Pair ID:** 1683_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1683_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.

- (BOOL) isCalendarDAVAccessEnabled;
- (BOOL) isAddressBookDAVAccessEnabled;

- (BOOL) enableEMailAlarms;

- (NSString *) faviconRelativeURL;
- (NSString *) zipPath;
- (int) port;
- (int) workers;
- (NSString *) logFile;
- (NSString *) pidFile;

- (NSTimeInterval) cacheCleanupInterval;
- (NSString *) memcachedHost;

- (BOOL) userCanChangePassword;
- (BOOL) uixAdditionalPreferences;

- (BOOL) uixDebugEnabled;
- (BOOL) easDebugEnabled;

- (NSString *) pageTitle;
- (NSString *) helpURL;

- (NSArray *) supportedLanguages;
- (NSString *) loginSuffix;

- (NSString *) authenticationType;
- (NSString *) davAuthenticationType;

- (NSString *) CASServiceURL;
- (BOOL) CASLogoutEnabled;

- (NSString *) SAML2PrivateKeyLocation;
- (NSString *) SAML2CertificateLocation;
- (NSString *) SAML2IdpMetadataLocation;
- (NSString *) SAML2IdpPublicKeyLocation;
- (NSString *) SAML2IdpCertificateLocation;
- (NSString *) SAML2LoginAttribute;
- (BOOL) SAML2LogoutEnabled;
- (NSString *) SAML2LogoutURL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,7 @@
 
 - (BOOL) uixDebugEnabled;
 - (BOOL) easDebugEnabled;
+- (BOOL) xsrfValidationEnabled;
 
 - (NSString *) pageTitle;
 - (NSString *) helpURL;
```
