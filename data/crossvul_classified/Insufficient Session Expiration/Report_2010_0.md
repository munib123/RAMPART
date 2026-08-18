# CrossVul Fix Pair: Insufficient Session Expiration in php
**Pair ID:** 2010_0
**Vulnerability Class:** Insufficient Session Expiration
**CWE:** CWE-613
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2010_0`)

## Vulnerability Information & PoC

## Description
Insufficient Session Expiration - According to WASC, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

## Vulnerable Code
```php
Lines 669-709 of the vulnerable file.

    public function logout()
    {
        // Initialize the current auth session before trying to remove it
        if (is_null($this->user) && !$this->check()) {
            return;
        }

        if ($this->isImpersonator()) {
            $this->user = $this->getImpersonator();
            $this->stopImpersonate();
            return;
        }

        if ($this->user) {
            $this->user->setRememberToken(null);
            $this->user->forceSave();
        }

        $this->user = null;

        Session::flush();
        Cookie::queue(Cookie::forget($this->sessionKey));
    }

    //
    // Impersonation
    //

    /**
     * Impersonates the given user and sets properties
     * in the session but not the cookie.
     */
    public function impersonate($user)
    {
        $oldSession = Session::get($this->sessionKey);
        $oldUser = !empty($oldSession[0]) ? $this->findUserById($oldSession[0]) : false;

        /**
         * @event model.auth.beforeImpersonate
         * Called after the model is booted
         *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -686,7 +686,7 @@
 
         $this->user = null;
 
-        Session::flush();
+        Session::invalidate();
         Cookie::queue(Cookie::forget($this->sessionKey));
     }
 
```
