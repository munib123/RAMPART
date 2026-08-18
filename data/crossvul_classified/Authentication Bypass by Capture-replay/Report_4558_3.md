# CrossVul Fix Pair: Authentication Bypass by Capture-replay in csharp
**Pair ID:** 4558_3
**Vulnerability Class:** Authentication Bypass by Capture-replay
**CWE:** CWE-294
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4558_3`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Capture-replay - Capture-replay attacks are common and can be difficult to defeat without cryptography.

## Vulnerable Code
```csharp
Lines 1901-1942 of the vulnerable file.


            responseXML = SignedXmlHelper.SignXml(responseXML);

            var response = Saml2Response.Read(responseXML, null);

            var options = StubFactory.CreateOptions();
            options.SPOptions.MinIncomingSigningAlgorithm = SecurityAlgorithms.RsaSha512Signature;

            Action a = () =>
            {
                response.GetClaims(options);
            };

            a.Should().Throw<InvalidSignatureException>()
                .WithMessage("*rsa-sha256*weak*rsa-sha512*");
        }

        [TestMethod]
        public void Saml2Response_GetClaims_ThrowsOnReplayAssertionId()
        {
            Assert.Inconclusive("Deliberately ignored test for now");

            var response =
            @"<?xml version=""1.0"" encoding=""UTF-8""?>
            <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID = """ + MethodBase.GetCurrentMethod().Name + @""" Version=""2.0"" IssueInstant=""2013-01-01T00:00:00Z"">
                <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                <saml2p:Status>
                    <saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" />
                </saml2p:Status>
                <saml2:Assertion
                Version=""2.0"" ID=""" + MethodBase.GetCurrentMethod().Name + @"_Assertion""
                IssueInstant=""2013-09-25T00:00:00Z"">
                    <saml2:Issuer>https://idp.example.com</saml2:Issuer>
                    <saml2:Subject>
                        <saml2:NameID>SomeUser</saml2:NameID>
                        <saml2:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" />
                    </saml2:Subject>
                    <saml2:Conditions NotOnOrAfter=""2100-01-01T00:00:00Z"" />
                </saml2:Assertion>
            </saml2p:Response>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1918,8 +1918,6 @@
         [TestMethod]
         public void Saml2Response_GetClaims_ThrowsOnReplayAssertionId()
         {
-            Assert.Inconclusive("Deliberately ignored test for now");
-
             var response =
             @"<?xml version=""1.0"" encoding=""UTF-8""?>
             <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
@@ -1955,8 +1953,6 @@
         [TestMethod]
         public void Saml2Response_GetClaims_ThrowsOnReplayAssertionIdSameConfig()
         {
-            Assert.Inconclusive("Ingored for now");
-
             var response =
             @"<?xml version=""1.0"" encoding=""UTF-8""?>
             <saml2p:Response xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
```
