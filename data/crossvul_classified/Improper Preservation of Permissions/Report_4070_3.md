# CrossVul Fix Pair: Improper Preservation of Permissions in go
**Pair ID:** 4070_3
**Vulnerability Class:** Improper Preservation of Permissions
**CWE:** CWE-281
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4070_3`)

## Vulnerability Information & PoC

## Description
Improper Preservation of Permissions - The product does not preserve permissions or incorrectly preserves permissions when copying, restoring, or sharing objects, which can cause them to have less restrictive permissions than intended.

## Vulnerable Code
```go
Lines 143-183 of the vulnerable file.


func DeleteEmailAddress(email *EmailAddress) (err error) {
	if email.ID > 0 {
		_, err = x.Id(email.ID).Delete(new(EmailAddress))
	} else {
		_, err = x.Where("email=?", email.Email).Delete(new(EmailAddress))
	}
	return err
}

func DeleteEmailAddresses(emails []*EmailAddress) (err error) {
	for i := range emails {
		if err = DeleteEmailAddress(emails[i]); err != nil {
			return err
		}
	}

	return nil
}

func MakeEmailPrimary(email *EmailAddress) error {
	has, err := x.Get(email)
	if err != nil {
		return err
	} else if !has {
		return errors.EmailNotFound{Email: email.Email}
	}

	if !email.IsActivated {
		return errors.EmailNotVerified{Email: email.Email}
	}

	user := &User{ID: email.UID}
	has, err = x.Get(user)
	if err != nil {
		return err
	} else if !has {
		return errors.UserNotExist{UserID: email.UID}
	}

	// Make sure the former primary email doesn't disappear.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -160,12 +160,16 @@
 	return nil
 }
 
-func MakeEmailPrimary(email *EmailAddress) error {
+func MakeEmailPrimary(userID int64, email *EmailAddress) error {
 	has, err := x.Get(email)
 	if err != nil {
 		return err
 	} else if !has {
 		return errors.EmailNotFound{Email: email.Email}
+	}
+
+	if email.UID != userID {
+		return errors.New("not the owner of the email")
 	}
 
 	if !email.IsActivated {
```
