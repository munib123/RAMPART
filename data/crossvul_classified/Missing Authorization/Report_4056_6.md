# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4056_6
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4056_6`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 569-609 of the vulnerable file.


=begin

reset password with token and set new password

  result = User.password_reset_via_token(token,password)

returns

  result = user_model # user_model if token was verified

=end

  def self.password_reset_via_token(token, password)

    # check token
    user = by_reset_token(token)
    return if !user

    # reset password
    user.update!(password: password)

    # delete token
    Token.find_by(action: 'PasswordReset', name: token).destroy
    user
  end

=begin

update last login date and reset login_failed (is automatically done by auth and sso backend)

  user = User.find(123)
  result = user.update_last_login

returns

  result = new_user_model

=end

  def update_last_login
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -586,7 +586,7 @@
     return if !user
 
     # reset password
-    user.update!(password: password)
+    user.update!(password: password, verified: true)
 
     # delete token
     Token.find_by(action: 'PasswordReset', name: token).destroy
```
