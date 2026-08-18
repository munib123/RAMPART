# CrossVul Fix Pair: Improper Preservation of Permissions in go
**Pair ID:** 4070_4
**Vulnerability Class:** Improper Preservation of Permissions
**CWE:** CWE-281
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4070_4`)

## Vulnerability Information & PoC

## Description
Improper Preservation of Permissions - The product does not preserve permissions or incorrectly preserves permissions when copying, restoring, or sharing objects, which can cause them to have less restrictive permissions than intended.

## Vulnerable Code
```go
Lines 220-260 of the vulnerable file.

func SettingsEmails(c *context.Context) {
	c.Title("settings.emails")
	c.PageIs("SettingsEmails")

	emails, err := db.GetEmailAddresses(c.User.ID)
	if err != nil {
		c.ServerError("GetEmailAddresses", err)
		return
	}
	c.Data["Emails"] = emails

	c.Success(SETTINGS_EMAILS)
}

func SettingsEmailPost(c *context.Context, f form.AddEmail) {
	c.Title("settings.emails")
	c.PageIs("SettingsEmails")

	// Make emailaddress primary.
	if c.Query("_method") == "PRIMARY" {
		if err := db.MakeEmailPrimary(&db.EmailAddress{ID: c.QueryInt64("id")}); err != nil {
			c.ServerError("MakeEmailPrimary", err)
			return
		}

		c.SubURLRedirect("/user/settings/email")
		return
	}

	// Add Email address.
	emails, err := db.GetEmailAddresses(c.User.ID)
	if err != nil {
		c.ServerError("GetEmailAddresses", err)
		return
	}
	c.Data["Emails"] = emails

	if c.HasError() {
		c.Success(SETTINGS_EMAILS)
		return
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,7 +237,7 @@
 
 	// Make emailaddress primary.
 	if c.Query("_method") == "PRIMARY" {
-		if err := db.MakeEmailPrimary(&db.EmailAddress{ID: c.QueryInt64("id")}); err != nil {
+		if err := db.MakeEmailPrimary(c.UserID(), &db.EmailAddress{ID: c.QueryInt64("id")}); err != nil {
 			c.ServerError("MakeEmailPrimary", err)
 			return
 		}
```
