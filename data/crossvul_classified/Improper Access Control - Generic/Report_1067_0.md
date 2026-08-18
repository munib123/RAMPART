# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in go
**Pair ID:** 1067_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1067_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```go
Lines 307-347 of the vulnerable file.

		return
	}

	if !(ua.SelfRegistration || ua.IsAdmin) {
		log.Warning("Registration can only be used by admin role user when self-registration is off.")
		ua.SendForbiddenError(errors.New(""))
		return
	}

	user := models.User{}
	if err := ua.DecodeJSONReq(&user); err != nil {
		ua.SendBadRequestError(err)
		return
	}
	err := validate(user)
	if err != nil {
		log.Warningf("Bad request in Register: %v", err)
		ua.RenderError(http.StatusBadRequest, "register error:"+err.Error())
		return
	}
	userExist, err := dao.UserExists(user, "username")
	if err != nil {
		log.Errorf("Error occurred in Register: %v", err)
		ua.SendInternalServerError(errors.New("internal error"))
		return
	}
	if userExist {
		log.Warning("username has already been used!")
		ua.SendConflictError(errors.New("username has already been used"))
		return
	}
	emailExist, err := dao.UserExists(user, "email")
	if err != nil {
		log.Errorf("Error occurred in change user profile: %v", err)
		ua.SendInternalServerError(errors.New("internal error"))
		return
	}
	if emailExist {
		log.Warning("email has already been used!")
		ua.SendConflictError(errors.New("email has already been used"))
		return
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,6 +324,14 @@
 		ua.RenderError(http.StatusBadRequest, "register error:"+err.Error())
 		return
 	}
+
+	if !ua.IsAdmin && user.HasAdminRole {
+		msg := "Non-admin cannot create an admin user."
+		log.Errorf(msg)
+		ua.SendForbiddenError(errors.New(msg))
+		return
+	}
+
 	userExist, err := dao.UserExists(user, "username")
 	if err != nil {
 		log.Errorf("Error occurred in Register: %v", err)
@@ -346,6 +354,7 @@
 		ua.SendConflictError(errors.New("email has already been used"))
 		return
 	}
+
 	userID, err := dao.Register(user)
 	if err != nil {
 		log.Errorf("Error occurred in Register: %v", err)
```
