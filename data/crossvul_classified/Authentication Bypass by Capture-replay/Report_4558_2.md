# CrossVul Fix Pair: Authentication Bypass by Capture-replay in csharp
**Pair ID:** 4558_2
**Vulnerability Class:** Authentication Bypass by Capture-replay
**CWE:** CWE-294
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4558_2`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Capture-replay - Capture-replay attacks are common and can be difficult to defeat without cryptography.

## Vulnerable Code
```csharp
Lines 580-620 of the vulnerable file.


            return claimsIdentities;
        }

        private IEnumerable<ClaimsIdentity> CreateClaims(IOptions options, IdentityProvider idp)
        {
            Validate(options, idp);

            if (status != Saml2StatusCode.Success)
            {
                throw new UnsuccessfulSamlOperationException(
                    "The Saml2Response must have status success to extract claims.",
                    status, statusMessage, secondLevelStatus);
            }

			TokenValidationParameters validationParameters = new TokenValidationParameters();
			validationParameters.AuthenticationType = "Federation";
			validationParameters.RequireSignedTokens = false;
			validationParameters.ValidateIssuer = false;
            validationParameters.ValidAudience = options.SPOptions.EntityId.Id;

            options.Notifications.Unsafe.TokenValidationParametersCreated(validationParameters, idp, XmlElement);

			var handler = options.SPOptions.Saml2PSecurityTokenHandler;

			foreach (XmlElement assertionNode in GetAllAssertionElementNodes(options))
            {
                var principal = handler.ValidateToken(assertionNode.OuterXml, validationParameters, out SecurityToken baseToken);
                var token = (Saml2SecurityToken)baseToken;
                options.SPOptions.Logger.WriteVerbose("Extracted SAML assertion " + token.Id);

				sessionNotOnOrAfter = DateTimeHelper.EarliestTime(sessionNotOnOrAfter,
					token.Assertion.Statements.OfType<Saml2AuthenticationStatement>()
						.SingleOrDefault()?.SessionNotOnOrAfter);

				foreach (var identity in principal.Identities)
				{
					yield return identity;
				}
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -597,6 +597,9 @@
 			validationParameters.RequireSignedTokens = false;
 			validationParameters.ValidateIssuer = false;
             validationParameters.ValidAudience = options.SPOptions.EntityId.Id;
+            validationParameters.RequireAudience = false; // Audience restriction optional in SAML2 spec.
+            validationParameters.TokenReplayCache = options.SPOptions.TokenReplayCache;
+            validationParameters.ValidateTokenReplay = true;
 
             options.Notifications.Unsafe.TokenValidationParametersCreated(validationParameters, idp, XmlElement);
 
```
