# CrossVul Fix Pair: Improper Authentication in go
**Pair ID:** 2806_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2806_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```go
Lines 37-77 of the vulnerable file.

	LDAPResultInsufficientAccessRights     = 50
	LDAPResultBusy                         = 51
	LDAPResultUnavailable                  = 52
	LDAPResultUnwillingToPerform           = 53
	LDAPResultLoopDetect                   = 54
	LDAPResultNamingViolation              = 64
	LDAPResultObjectClassViolation         = 65
	LDAPResultNotAllowedOnNonLeaf          = 66
	LDAPResultNotAllowedOnRDN              = 67
	LDAPResultEntryAlreadyExists           = 68
	LDAPResultObjectClassModsProhibited    = 69
	LDAPResultAffectsMultipleDSAs          = 71
	LDAPResultOther                        = 80

	ErrorNetwork            = 200
	ErrorFilterCompile      = 201
	ErrorFilterDecompile    = 202
	ErrorDebugging          = 203
	ErrorUnexpectedMessage  = 204
	ErrorUnexpectedResponse = 205
)

// LDAPResultCodeMap contains string descriptions for LDAP error codes
var LDAPResultCodeMap = map[uint8]string{
	LDAPResultSuccess:                      "Success",
	LDAPResultOperationsError:              "Operations Error",
	LDAPResultProtocolError:                "Protocol Error",
	LDAPResultTimeLimitExceeded:            "Time Limit Exceeded",
	LDAPResultSizeLimitExceeded:            "Size Limit Exceeded",
	LDAPResultCompareFalse:                 "Compare False",
	LDAPResultCompareTrue:                  "Compare True",
	LDAPResultAuthMethodNotSupported:       "Auth Method Not Supported",
	LDAPResultStrongAuthRequired:           "Strong Auth Required",
	LDAPResultReferral:                     "Referral",
	LDAPResultAdminLimitExceeded:           "Admin Limit Exceeded",
	LDAPResultUnavailableCriticalExtension: "Unavailable Critical Extension",
	LDAPResultConfidentialityRequired:      "Confidentiality Required",
	LDAPResultSaslBindInProgress:           "Sasl Bind In Progress",
	LDAPResultNoSuchAttribute:              "No Such Attribute",
	LDAPResultUndefinedAttributeType:       "Undefined Attribute Type",
	LDAPResultInappropriateMatching:        "Inappropriate Matching",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,6 +54,7 @@
 	ErrorDebugging          = 203
 	ErrorUnexpectedMessage  = 204
 	ErrorUnexpectedResponse = 205
+	ErrorEmptyPassword      = 206
 )
 
 // LDAPResultCodeMap contains string descriptions for LDAP error codes
@@ -104,6 +105,7 @@
 	ErrorDebugging:          "Debugging Error",
 	ErrorUnexpectedMessage:  "Unexpected Message",
 	ErrorUnexpectedResponse: "Unexpected Response",
+	ErrorEmptyPassword:      "Empty password not allowed by the client",
 }
 
 func getLDAPResultCode(packet *ber.Packet) (code uint8, description string) {
```
