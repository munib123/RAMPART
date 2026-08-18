# CrossVul Fix Pair: Key Management Errors in csharp
**Pair ID:** 636_4
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `636_4`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```csharp
Lines 214-255 of the vulnerable file.

            configuration.ServerConfiguration.MaxRegistrationInterval = 0;

            // Step 5 - Specify the based addresses - one per binding specified above.
            configuration.ServerConfiguration.BaseAddresses.Add(DefaultHttpUrl);
            configuration.ServerConfiguration.BaseAddresses.Add(DefaultTcpUrl);

            // Step 6 - Specify the security policies.
          
            // Security policies control what security must be used to connect to the server.
            // The SDK will automatically create EndpointDescriptions for each combination of 
            // security policy and base address. 
            //
            // Note that some bindings only allow one policy per URL so the SDK will append 
            // text to the base addresses in order to ensure that each policy has a unique URL.
            // The first policy specified in the configuration is assigned the base address.

            // this policy requires signing and encryption.
            ServerSecurityPolicy policy1 = new ServerSecurityPolicy();

            policy1.SecurityMode      = MessageSecurityMode.SignAndEncrypt;
            policy1.SecurityPolicyUri = SecurityPolicies.Basic128Rsa15;
            policy1.SecurityLevel     = 1;

            configuration.ServerConfiguration.SecurityPolicies.Add(policy1);

            // this policy does not require any security.
            ServerSecurityPolicy policy2 = new ServerSecurityPolicy();

            policy2.SecurityMode      = MessageSecurityMode.None;
            policy2.SecurityPolicyUri = SecurityPolicies.None;
            policy2.SecurityLevel     = 0;

            configuration.ServerConfiguration.SecurityPolicies.Add(policy2);

            // specify the supported user token types.
            configuration.ServerConfiguration.UserTokenPolicies.Add(new UserTokenPolicy(UserTokenType.Anonymous));
            configuration.ServerConfiguration.UserTokenPolicies.Add(new UserTokenPolicy(UserTokenType.UserName));

            // Step 6 - Validate the configuration.
        
            // This step checks if the configuration is consistent and assigns a few internal variables
            // that are used by the SDK. This is called automatically if the configuration is loaded from
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -231,8 +231,8 @@
             ServerSecurityPolicy policy1 = new ServerSecurityPolicy();
 
             policy1.SecurityMode      = MessageSecurityMode.SignAndEncrypt;
-            policy1.SecurityPolicyUri = SecurityPolicies.Basic128Rsa15;
-            policy1.SecurityLevel     = 1;
+            policy1.SecurityPolicyUri = SecurityPolicies.Basic256Sha256;
+            policy1.SecurityLevel     = 5;
 
             configuration.ServerConfiguration.SecurityPolicies.Add(policy1);
 
@@ -279,7 +279,7 @@
             // specify the security policy to use.
             // endpointDescription.SecurityPolicyUri = SecurityPolicies.None;
             // endpointDescription.SecurityMode      = MessageSecurityMode.None;;
-            endpointDescription.SecurityPolicyUri = SecurityPolicies.Basic128Rsa15;
+            endpointDescription.SecurityPolicyUri = SecurityPolicies.Basic256Sha256;
             endpointDescription.SecurityMode      = MessageSecurityMode.SignAndEncrypt;
             
             // specify the transport profile.
```
