# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 826_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `826_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 36-60 of the vulnerable file.


    /**
     * @param ConfirmEmail $command
     * @return \Flarum\User\User
     */
    public function handle(ConfirmEmail $command)
    {
        /** @var EmailToken $token */
        $token = EmailToken::validOrFail($command->token);

        $user = $token->user;
        $user->changeEmail($token->email);

        if (! $user->is_activated) {
            $user->activate();
        }

        $user->save();
        $this->dispatchEventsFor($user);

        $token->delete();

        return $user;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,8 @@
         $user->save();
         $this->dispatchEventsFor($user);
 
-        $token->delete();
+        // Delete *all* tokens for the user, in case other ones were sent first
+        $user->emailTokens()->delete();
 
         return $user;
     }
```
