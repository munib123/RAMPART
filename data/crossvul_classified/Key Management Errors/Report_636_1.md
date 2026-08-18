# CrossVul Fix Pair: Key Management Errors in csharp
**Pair ID:** 636_1
**Vulnerability Class:** Key Management Errors
**CWE:** CWE-320
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `636_1`)

## Vulnerability Information & PoC

## Description
Key Management Errors

## Vulnerable Code
```csharp
Lines 884-924 of the vulnerable file.


            // filter by the current security mode.
            MessageSecurityMode currentMode = MessageSecurityMode.None;

            if (SecurityModeCB.SelectedIndex != -1)
            {
                currentMode = (MessageSecurityMode)SecurityModeCB.SelectedItem;
            }

            // preserve the existing value.
            string currentPolicy = (string)SecurityPolicyCB.SelectedItem;

            SecurityPolicyCB.Items.Clear();

            // set all available security policies.
            if (m_showAllOptions)
            {
                SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.None));
                SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.Basic128Rsa15));
                SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.Basic256));
            }

            // find all unique security policies.    
            else
            {
                if (endpoints != null)
                {
                    foreach (EndpointDescription endpoint in endpoints)
                    {
                        Uri url = Utils.ParseUri(endpoint.EndpointUrl);

                        if ((url != null) && (currentProtocol != null))
                        {
                            if (!currentProtocol.Matches(url))
                            {
                                continue;
                            }

                            if (currentMode != endpoint.SecurityMode)
                            {
                                continue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -901,6 +901,7 @@
                 SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.None));
                 SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.Basic128Rsa15));
                 SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.Basic256));
+                SecurityPolicyCB.Items.Add(SecurityPolicies.GetDisplayName(SecurityPolicies.Basic256Sha256));
             }
 
             // find all unique security policies.    
```
