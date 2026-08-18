# CrossVul Fix Pair: Improper Authentication in go
**Pair ID:** 3897_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3897_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```go
Lines 123-163 of the vulnerable file.


func validateAdminSignature(ctx context.Context, r *http.Request, region string) (auth.Credentials, map[string]interface{}, bool, APIErrorCode) {
	var cred auth.Credentials
	var owner bool
	s3Err := ErrAccessDenied
	if _, ok := r.Header[xhttp.AmzContentSha256]; ok &&
		getRequestAuthType(r) == authTypeSigned && !skipContentSha256Cksum(r) {
		// We only support admin credentials to access admin APIs.
		cred, owner, s3Err = getReqAccessKeyV4(r, region, serviceS3)
		if s3Err != ErrNone {
			return cred, nil, owner, s3Err
		}

		// we only support V4 (no presign) with auth body
		s3Err = isReqAuthenticated(ctx, r, region, serviceS3)
	}
	if s3Err != ErrNone {
		reqInfo := (&logger.ReqInfo{}).AppendTags("requestHeaders", dumpRequest(r))
		ctx := logger.SetReqInfo(ctx, reqInfo)
		logger.LogIf(ctx, errors.New(getAPIError(s3Err).Description), logger.Application)
	}

	claims, s3Err := checkClaimsFromToken(r, cred)
	if s3Err != ErrNone {
		return cred, nil, owner, s3Err
	}

	return cred, claims, owner, ErrNone
}

// checkAdminRequestAuthType checks whether the request is a valid signature V2 or V4 request.
// It does not accept presigned or JWT or anonymous requests.
func checkAdminRequestAuthType(ctx context.Context, r *http.Request, action iampolicy.AdminAction, region string) (auth.Credentials, APIErrorCode) {
	cred, claims, owner, s3Err := validateAdminSignature(ctx, r, region)
	if s3Err != ErrNone {
		return cred, s3Err
	}
	if globalIAMSys.IsAllowed(iampolicy.Args{
		AccountName:     cred.AccessKey,
		Action:          iampolicy.Action(action),
		ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,6 +140,7 @@
 		reqInfo := (&logger.ReqInfo{}).AppendTags("requestHeaders", dumpRequest(r))
 		ctx := logger.SetReqInfo(ctx, reqInfo)
 		logger.LogIf(ctx, errors.New(getAPIError(s3Err).Description), logger.Application)
+		return cred, nil, owner, s3Err
 	}
 
 	claims, s3Err := checkClaimsFromToken(r, cred)
```
