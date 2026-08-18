# CrossVul Fix Pair: Insufficient Session Expiration in go
**Pair ID:** 1982_0
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1982_0`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```go
Lines 264-304 of the vulnerable file.


	subject := jwtutil.StringField(claims, "sub")
	id := jwtutil.StringField(claims, "jti")

	if projName, role, ok := rbacpolicy.GetProjectRoleFromSubject(subject); ok {
		proj, err := mgr.projectsLister.Get(projName)
		if err != nil {
			return nil, err
		}
		_, _, err = proj.GetJWTToken(role, issuedAt.Unix(), id)
		if err != nil {
			return nil, err
		}

		return token.Claims, nil
	}

	account, err := mgr.settingsMgr.GetAccount(subject)
	if err != nil {
		return nil, err
	}

	if id := jwtutil.StringField(claims, "jti"); id != "" && account.TokenIndex(id) == -1 {
		return nil, fmt.Errorf("account %s does not have token with id %s", subject, id)
	}

	if account.PasswordMtime != nil && issuedAt.Before(*account.PasswordMtime) {
		return nil, fmt.Errorf("Account password has changed since token issued")
	}
	return token.Claims, nil
}

// GetLoginFailures retrieves the login failure information from the cache
func (mgr *SessionManager) GetLoginFailures() map[string]LoginAttempts {
	// Get failures from the cache
	var failures map[string]LoginAttempts
	err := mgr.storage.GetLoginAttempts(&failures)
	if err != nil {
		if err != appstate.ErrCacheMiss {
			log.Errorf("Could not retrieve login attempts: %v", err)
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -281,6 +281,10 @@
 	account, err := mgr.settingsMgr.GetAccount(subject)
 	if err != nil {
 		return nil, err
+	}
+
+	if !account.Enabled {
+		return nil, fmt.Errorf("account %s is disabled", subject)
 	}
 
 	if id := jwtutil.StringField(claims, "jti"); id != "" && account.TokenIndex(id) == -1 {
```
