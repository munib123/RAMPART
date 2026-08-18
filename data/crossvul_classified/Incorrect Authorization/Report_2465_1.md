# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 2465_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2465_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 70-106 of the vulnerable file.

        }

        $request = $event->getRequest();

        $attributes = $request->attributes->get('_access_control_attributes');
        $request->attributes->remove('_access_control_attributes');

        if (!$attributes || ([AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY] === $attributes && $event instanceof LazyResponseEvent)) {
            return;
        }

        if ($event instanceof LazyResponseEvent && null === $token = $this->tokenStorage->getToken()) {
            throw new AuthenticationCredentialsNotFoundException('A Token was not found in the TokenStorage.');
        }

        if (!$token->isAuthenticated()) {
            $token = $this->authManager->authenticate($token);
            $this->tokenStorage->setToken($token);
        }

        $granted = false;
        foreach ($attributes as $key => $value) {
            if ($this->accessDecisionManager->decide($token, [$key => $value], $request)) {
                $granted = true;
                break;
            }
        }

        if (!$granted) {
            $exception = new AccessDeniedException();
            $exception->setAttributes($attributes);
            $exception->setSubject($request);

            throw $exception;
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,15 +87,7 @@
             $this->tokenStorage->setToken($token);
         }
 
-        $granted = false;
-        foreach ($attributes as $key => $value) {
-            if ($this->accessDecisionManager->decide($token, [$key => $value], $request)) {
-                $granted = true;
-                break;
-            }
-        }
-
-        if (!$granted) {
+        if (!$this->accessDecisionManager->decide($token, $attributes, $request, true)) {
             $exception = new AccessDeniedException();
             $exception->setAttributes($attributes);
             $exception->setSubject($request);
```
