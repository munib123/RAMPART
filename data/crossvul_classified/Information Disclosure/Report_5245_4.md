# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5245_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5245_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 24-47 of the vulnerable file.

    def logout_url
      nil
    end

    # don't forget to implement expiration_url method if your SSO method changes this to true
    def support_expiration?
      false
    end

    # if your SSO method supports logout page, you should store it into a session[:logout_url]
    # during this method execution
    def authenticated?
      raise NotImplementedError, "#{__method__} not implemented for this authentication method"
    end

    def authenticate!
      raise NotImplementedError, "#{__method__} not implemented for this authentication method"
    end

    def current_user
      User.except_hidden.find_by_login(self.user)
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,7 @@
     end
 
     def current_user
-      User.except_hidden.find_by_login(self.user)
+      User.unscoped.except_hidden.find_by_login(self.user)
     end
   end
 end
```
