# CrossVul Fix Pair: Improper Authentication in go
**Pair ID:** 4168_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4168_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```go
Lines 189-229 of the vulnerable file.

	ErrRequestURINotSupported = &RFC6749Error{
		Description: "The OP does not support use of the request_uri parameter",
		Name:        errRequestURINotSupportedName,
		Code:        http.StatusBadRequest,
	}
	ErrRegistrationNotSupported = &RFC6749Error{
		Description: "The OP does not support use of the registration parameter",
		Name:        errRegistrationNotSupportedName,
		Code:        http.StatusBadRequest,
	}
	ErrInvalidRequestURI = &RFC6749Error{
		Description: "The request_uri in the Authorization Request returns an error or contains invalid data. ",
		Name:        errInvalidRequestURI,
		Code:        http.StatusBadRequest,
	}
	ErrInvalidRequestObject = &RFC6749Error{
		Description: "The request parameter contains an invalid Request Object. ",
		Name:        errInvalidRequestObject,
		Code:        http.StatusBadRequest,
	}
)

const (
	errInvalidRequestURI            = "invalid_request_uri"
	errInvalidRequestObject         = "invalid_request_object"
	errConsentRequired              = "consent_required"
	errInteractionRequired          = "interaction_required"
	errLoginRequired                = "login_required"
	errRequestUnauthorizedName      = "request_unauthorized"
	errRequestForbidden             = "request_forbidden"
	errInvalidRequestName           = "invalid_request"
	errUnauthorizedClientName       = "unauthorized_client"
	errAccessDeniedName             = "access_denied"
	errUnsupportedResponseTypeName  = "unsupported_response_type"
	errInvalidScopeName             = "invalid_scope"
	errServerErrorName              = "server_error"
	errTemporarilyUnavailableName   = "temporarily_unavailable"
	errUnsupportedGrantTypeName     = "unsupported_grant_type"
	errInvalidGrantName             = "invalid_grant"
	errInvalidClientName            = "invalid_client"
	errNotFoundName                 = "not_found"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,6 +204,11 @@
 	ErrInvalidRequestObject = &RFC6749Error{
 		Description: "The request parameter contains an invalid Request Object. ",
 		Name:        errInvalidRequestObject,
+		Code:        http.StatusBadRequest,
+	}
+	ErrJTIKnown = &RFC6749Error{
+		Description: "The jti was already used.",
+		Name:        errJTIKnownName,
 		Code:        http.StatusBadRequest,
 	}
 )
@@ -242,6 +247,7 @@
 	errRequestNotSupportedName      = "request_not_supported"
 	errRequestURINotSupportedName   = "request_uri_not_supported"
 	errRegistrationNotSupportedName = "registration_not_supported"
+	errJTIKnownName                 = "jti_known"
 )
 
 func ErrorToRFC6749Error(err error) *RFC6749Error {
```
