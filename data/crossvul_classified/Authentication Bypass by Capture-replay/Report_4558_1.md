# CrossVul Fix Pair: Authentication Bypass by Capture-replay in csharp
**Pair ID:** 4558_1
**Vulnerability Class:** Authentication Bypass by Capture-replay
**CWE:** CWE-294
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4558_1`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Capture-replay - Capture-replay attacks are common and can be difficult to defeat without cryptography.

## Vulnerable Code
```csharp
Lines 9-61 of the vulnerable file.


namespace Sustainsys.Saml2.Saml2P
{
	/// <summary>
	/// Somewhat ugly subclassing to be able to access some methods that are protected
	/// on Saml2SecurityTokenHandler. The public interface of Saml2SecurityTokenHandler
	/// expects the actual assertion to be signed, which is not always the case when
	/// using Saml2-P. The assertion can be embedded in a signed response. Or the signing
	/// could be handled at transport level.
	/// </summary>
	public class Saml2PSecurityTokenHandler : Saml2SecurityTokenHandler
	{
		public Saml2PSecurityTokenHandler(): this(null)
		{
			// backward compatibility = null spOptions
		}

		public Saml2PSecurityTokenHandler(SPOptions spOptions)
		{
			Serializer = new Saml2PSerializer(spOptions);
		}

		// Overridden to fix the fact that the base class version uses NotBefore as the token replay expiry time
		// Due to the fact that we can't override the ValidateToken function (it's overridden in the base class!)
		// we have to parse the token again.
		// This can be removed when:
		// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/898
		// is fixed.
		protected override void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
		{
			var saml2Token = ReadSaml2Token(securityToken);
			base.ValidateTokenReplay(saml2Token.Assertion.Conditions.NotOnOrAfter,
				securityToken, validationParameters);
		}

		// TODO: needed with Microsoft.identitymodel?
		/// <summary>
		/// Process authentication statement from SAML assertion. WIF chokes if the authentication statement 
		/// contains a DeclarationReference, so we clear this out before calling the base method
		/// http://referencesource.microsoft.com/#System.IdentityModel/System/IdentityModel/Tokens/Saml2SecurityTokenHandler.cs,1970
		/// </summary>
		/// <param name="statement">Authentication statement</param>
		/// <param name="subject">Claim subject</param>
		/// <param name="issuer">Assertion Issuer</param>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "1")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0")]
        protected override void ProcessAuthenticationStatement(Saml2AuthenticationStatement statement, ClaimsIdentity subject, string issuer)
        {
            if (statement.AuthenticationContext != null)
            {
                statement.AuthenticationContext.DeclarationReference = null;
            }
            base.ProcessAuthenticationStatement(statement, subject, issuer);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,19 +26,6 @@
 		public Saml2PSecurityTokenHandler(SPOptions spOptions)
 		{
 			Serializer = new Saml2PSerializer(spOptions);
-		}
-
-		// Overridden to fix the fact that the base class version uses NotBefore as the token replay expiry time
-		// Due to the fact that we can't override the ValidateToken function (it's overridden in the base class!)
-		// we have to parse the token again.
-		// This can be removed when:
-		// https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/898
-		// is fixed.
-		protected override void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
-		{
-			var saml2Token = ReadSaml2Token(securityToken);
-			base.ValidateTokenReplay(saml2Token.Assertion.Conditions.NotOnOrAfter,
-				securityToken, validationParameters);
 		}
 
 		// TODO: needed with Microsoft.identitymodel?
@@ -84,10 +71,27 @@
             }
         }
 
-		protected override Saml2SecurityToken ValidateSignature(string token, TokenValidationParameters validationParameters)
+		// Override and build our own logic. The problem is ValidateTokenReplay that serializes the token back. And that
+		// breaks because it expects some optional values to be present.
+		public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out Microsoft.IdentityModel.Tokens.SecurityToken validatedToken)
 		{
-			// Just skip signature validation -- we do this elsewhere
-			return ReadSaml2Token(token);
+			var samlToken = ReadSaml2Token(token);
+
+			ValidateConditions(samlToken, validationParameters);
+			ValidateSubject(samlToken, validationParameters);
+
+			var issuer = ValidateIssuer(samlToken.Issuer, samlToken, validationParameters);
+
+			// Just using the assertion id for token replay. As that is part of the signed value it cannot
+			// be altered by someone replaying the token.
+			ValidateTokenReplay(samlToken.Assertion.Conditions.NotOnOrAfter, samlToken.Assertion.Id.Value, validationParameters);
+
+			// ValidateIssuerSecurityKey not called - we have our own signature validation.
+
+			validatedToken = samlToken;
+			var identity = CreateClaimsIdentity(samlToken, issuer, validationParameters);
+
+			return new ClaimsPrincipal(identity);
 		}
-    }
+	}
 }
```
