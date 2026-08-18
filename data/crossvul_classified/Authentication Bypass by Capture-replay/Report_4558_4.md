# CrossVul Fix Pair: Authentication Bypass by Capture-replay in csharp
**Pair ID:** 4558_4
**Vulnerability Class:** Authentication Bypass by Capture-replay
**CWE:** CWE-294
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4558_4`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Capture-replay - Capture-replay attacks are common and can be difficult to defeat without cryptography.

## Vulnerable Code
```csharp
Lines 121-162 of the vulnerable file.

        }

        [TestMethod]
        public void Saml2ArtifactBinding_Unbind_FromGet_ArtifactIsntHashOfEntityId()
        {
            var issuer = new EntityId("https://idp.example.com");
            var artifact = Uri.EscapeDataString(
                Convert.ToBase64String(
                    Saml2ArtifactBinding.CreateArtifact(
                        new EntityId("https://this.entityid.is.invalid"),
                        0x1234)));

            var relayState = "relayState";

            var r = new HttpRequestData(
                "GET",
                new Uri($"http://example.com/path/acs?SAMLart={artifact}&RelayState={relayState}"),
                null,
                null,
                new StoredRequestState(issuer, null, null, null));

            StubServer.LastArtifactResolutionSoapActionHeader = null;

            var result = Saml2Binding.Get(Saml2BindingType.Artifact).Unbind(r, StubFactory.CreateOptions());

            var xmlDocument = XmlHelpers.XmlDocumentFromString(
                "<message>   <child-node /> </message>");

            var expected = new UnbindResult(xmlDocument.DocumentElement, relayState, TrustLevel.None);

            result.Should().BeEquivalentTo(expected);
            StubServer.LastArtifactResolutionWasSigned.Should().BeFalse();
        }

        [TestMethod]
        public void Saml2ArtifactBinding_Unbind_FromGet_SignsArtifactResolve()
        {
            var issuer = new EntityId("https://idp.example.com");
            var artifact = Uri.EscapeDataString(
                Convert.ToBase64String(
                    Saml2ArtifactBinding.CreateArtifact(issuer, 0x1234)));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,8 +139,6 @@
                 null,
                 new StoredRequestState(issuer, null, null, null));
 
-            StubServer.LastArtifactResolutionSoapActionHeader = null;
-
             var result = Saml2Binding.Get(Saml2BindingType.Artifact).Unbind(r, StubFactory.CreateOptions());
 
             var xmlDocument = XmlHelpers.XmlDocumentFromString(
```
