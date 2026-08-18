# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in csharp
**Pair ID:** 4352_2
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4352_2`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```csharp
Lines 39-79 of the vulnerable file.

            public const string GcmTrace              = "GCM_TRACE";
            public const string GcmTraceSecrets       = "GCM_TRACE_SECRETS";
            public const string GcmTraceMsAuth        = "GCM_TRACE_MSAUTH";
            public const string GcmDebug              = "GCM_DEBUG";
            public const string GcmProvider           = "GCM_PROVIDER";
            public const string GcmAuthority          = "GCM_AUTHORITY";
            public const string GitTerminalPrompts    = "GIT_TERMINAL_PROMPT";
            public const string GcmAllowWia           = "GCM_ALLOW_WINDOWSAUTH";
            public const string CurlAllProxy          = "ALL_PROXY";
            public const string CurlHttpProxy         = "HTTP_PROXY";
            public const string CurlHttpsProxy        = "HTTPS_PROXY";
            public const string GcmHttpProxy          = "GCM_HTTP_PROXY";
            public const string GitSslNoVerify        = "GIT_SSL_NO_VERIFY";
            public const string GcmInteractive        = "GCM_INTERACTIVE";
            public const string GcmParentWindow       = "GCM_MODAL_PARENTHWND";
            public const string MsAuthFlow            = "GCM_MSAUTH_FLOW";
            public const string MsAuthHelper          = "GCM_MSAUTH_HELPER";
            public const string GcmCredNamespace      = "GCM_NAMESPACE";
            public const string GcmCredentialStore    = "GCM_CREDENTIAL_STORE";
            public const string GcmPlaintextStorePath = "GCM_PLAINTEXT_STORE_PATH";
        }

        public static class Http
        {
            public const string WwwAuthenticateBasicScheme     = "Basic";
            public const string WwwAuthenticateBearerScheme    = "Bearer";
            public const string WwwAuthenticateNegotiateScheme = "Negotiate";
            public const string WwwAuthenticateNtlmScheme      = "NTLM";

            public const string MimeTypeJson = "application/json";
        }

        public static class GitConfiguration
        {
            public static class Credential
            {
                public const string SectionName = "credential";
                public const string Helper      = "helper";
                public const string Provider    = "provider";
                public const string Authority   = "authority";
                public const string AllowWia    = "allowWindowsAuth";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
             public const string GcmCredNamespace      = "GCM_NAMESPACE";
             public const string GcmCredentialStore    = "GCM_CREDENTIAL_STORE";
             public const string GcmPlaintextStorePath = "GCM_PLAINTEXT_STORE_PATH";
+            public const string GitExecutablePath     = "GIT_EXEC_PATH";
         }
 
         public static class Http
```
