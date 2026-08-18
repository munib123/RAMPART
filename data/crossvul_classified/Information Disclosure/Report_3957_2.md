# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in go
**Pair ID:** 3957_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3957_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```go
Lines 139-179 of the vulnerable file.

	account, err := mgr.settingsMgr.GetAccount(subject)
	if err != nil {
		return nil, err
	}

	if id := jwtutil.GetField(claims, "jti"); id != "" && account.TokenIndex(id) == -1 {
		return nil, fmt.Errorf("account %s does not have token with id %s", subject, id)
	}

	issuedAt := time.Unix(int64(claims["iat"].(float64)), 0)
	if account.PasswordMtime != nil && issuedAt.Before(*account.PasswordMtime) {
		return nil, fmt.Errorf("Account password has changed since token issued")
	}
	return token.Claims, nil
}

// VerifyUsernamePassword verifies if a username/password combo is correct
func (mgr *SessionManager) VerifyUsernamePassword(username string, password string) error {
	account, err := mgr.settingsMgr.GetAccount(username)
	if err != nil {
		return err
	}
	if !account.Enabled {
		return status.Errorf(codes.Unauthenticated, accountDisabled, username)
	}
	if password == "" {
		return status.Errorf(codes.Unauthenticated, blankPasswordError)
	}

	valid, _ := passwordutil.VerifyPassword(password, account.PasswordHash)
	if !valid {
		return status.Errorf(codes.Unauthenticated, invalidLoginError)
	}
	return nil
}

// VerifyToken verifies if a token is correct. Tokens can be issued either from us or by an IDP.
// We choose how to verify based on the issuer.
func (mgr *SessionManager) VerifyToken(tokenString string) (jwt.Claims, error) {
	parser := &jwt.Parser{
		SkipClaimsValidation: true,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,6 +156,9 @@
 func (mgr *SessionManager) VerifyUsernamePassword(username string, password string) error {
 	account, err := mgr.settingsMgr.GetAccount(username)
 	if err != nil {
+		if errStatus, ok := status.FromError(err); ok && errStatus.Code() == codes.NotFound {
+			err = status.Errorf(codes.Unauthenticated, invalidLoginError)
+		}
 		return err
 	}
 	if !account.Enabled {
```
