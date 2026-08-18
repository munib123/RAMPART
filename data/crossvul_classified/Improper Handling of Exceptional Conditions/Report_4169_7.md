# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in go
**Pair ID:** 4169_7
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4169_7`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```go
Lines 40-77 of the vulnerable file.

func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) error {
	discoveryFuncs := []func() (request fosite.Requester, err error){
		func() (request fosite.Requester, err error) {
			// Refresh token
			signature := r.RefreshTokenStrategy.RefreshTokenSignature(token)
			return r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
		},
		func() (request fosite.Requester, err error) {
			// Access token
			signature := r.AccessTokenStrategy.AccessTokenSignature(token)
			return r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil)
		},
	}

	// Token type hinting
	if tokenType == fosite.AccessToken {
		discoveryFuncs[0], discoveryFuncs[1] = discoveryFuncs[1], discoveryFuncs[0]
	}

	var ar fosite.Requester
	var err error
	if ar, err = discoveryFuncs[0](); err != nil {
		ar, err = discoveryFuncs[1]()
	}
	if err != nil {
		return err
	}

	if ar.GetClient().GetID() != client.GetID() {
		return errors.WithStack(fosite.ErrRevocationClientMismatch)
	}

	requestID := ar.GetID()
	r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
	r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)

	return nil
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,21 +57,32 @@
 	}
 
 	var ar fosite.Requester
-	var err error
-	if ar, err = discoveryFuncs[0](); err != nil {
-		ar, err = discoveryFuncs[1]()
+	var err1, err2 error
+	if ar, err1 = discoveryFuncs[0](); err1 != nil {
+		ar, err2 = discoveryFuncs[1]()
 	}
-	if err != nil {
-		return err
+	// err2 can only be not nil if first err1 was not nil
+	if err2 != nil {
+		return storeErrorsToRevocationError(err1, err2)
 	}
 
 	if ar.GetClient().GetID() != client.GetID() {
-		return errors.WithStack(fosite.ErrRevocationClientMismatch)
+		return errors.WithStack(fosite.ErrUnauthorizedClient)
 	}
 
 	requestID := ar.GetID()
-	r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
-	r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)
+	err1 = r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
+	err2 = r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)
 
-	return nil
+	return storeErrorsToRevocationError(err1, err2)
 }
+
+func storeErrorsToRevocationError(err1, err2 error) error {
+	// both errors are 404 or nil <=> the token is revoked
+	if (errors.Is(err1, fosite.ErrNotFound) || err1 == nil) && (errors.Is(err2, fosite.ErrNotFound) || err2 == nil) {
+		return nil
+	}
+
+	// there was an unexpected error => the token may still exist and the client should retry later
+	return errors.WithStack(fosite.ErrTemporarilyUnavailable)
+}
```
