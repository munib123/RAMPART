# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_4
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_4`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 145-189 of the vulnerable file.

		Hint:        "The token expired.",
		Code:        http.StatusUnauthorized,
	}
	ErrScopeNotGranted = &RFC6749Error{
		Name:        errScopeNotGrantedName,
		Description: "The token was not granted the requested scope",
		Hint:        "The resource owner did not grant the requested scope.",
		Code:        http.StatusForbidden,
	}
	ErrTokenClaim = &RFC6749Error{
		Name:        errTokenClaimName,
		Description: "The token failed validation due to a claim mismatch",
		Hint:        "One or more token claims failed validation.",
		Code:        http.StatusUnauthorized,
	}
	ErrInactiveToken = &RFC6749Error{
		Name:        errTokenInactiveName,
		Description: "Token is inactive because it is malformed, expired or otherwise invalid",
		Hint:        "Token validation failed.",
		Code:        http.StatusUnauthorized,
	}
	ErrRevocationClientMismatch = &RFC6749Error{
		Name:        errRevocationClientMismatchName,
		Description: "Token was not issued to the client making the revocation request",
		Code:        http.StatusBadRequest,
	}
	ErrLoginRequired = &RFC6749Error{
		Name:        errLoginRequired,
		Description: "The Authorization Server requires End-User authentication",
		Code:        http.StatusBadRequest,
	}
	ErrInteractionRequired = &RFC6749Error{
		Description: "The Authorization Server requires End-User interaction of some form to proceed",
		Name:        errInteractionRequired,
		Code:        http.StatusBadRequest,
	}
	ErrConsentRequired = &RFC6749Error{
		Description: "The Authorization Server requires End-User consent",
		Name:        errConsentRequired,
		Code:        http.StatusBadRequest,
	}
	ErrRequestNotSupported = &RFC6749Error{
		Description: "The OP does not support use of the request parameter",
		Name:        errRequestNotSupportedName,
		Code:        http.StatusBadRequest,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -162,11 +162,6 @@
 		Description: "Token is inactive because it is malformed, expired or otherwise invalid",
 		Hint:        "Token validation failed.",
 		Code:        http.StatusUnauthorized,
-	}
-	ErrRevocationClientMismatch = &RFC6749Error{
-		Name:        errRevocationClientMismatchName,
-		Description: "Token was not issued to the client making the revocation request",
-		Code:        http.StatusBadRequest,
 	}
 	ErrLoginRequired = &RFC6749Error{
 		Name:        errLoginRequired,
```
