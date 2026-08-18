# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 4518_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4518_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 38-79 of the vulnerable file.

        Context $context,
        Crypto $crypto,
        TranslatorInterface $translator,
        $guest_allowed
    ) {
        $this->context = $context;
        $this->crypto = $crypto;
        $this->translator = $translator;
        $this->guest_allowed = $guest_allowed;
    }

    public function getErrors()
    {
        return $this->errors;
    }

    public function save(Customer $customer, $clearTextPassword, $newPassword = '', $passwordRequired = true)
    {
        if ($customer->id) {
            return $this->update($customer, $clearTextPassword, $newPassword, $passwordRequired);
        } else {
            return $this->create($customer, $clearTextPassword);
        }
    }

    private function update(Customer $customer, $clearTextPassword, $newPassword, $passwordRequired = true)
    {
        if (!$customer->is_guest && $passwordRequired && !$this->crypto->checkHash(
            $clearTextPassword,
            $customer->passwd,
            _COOKIE_KEY_
        )) {
            $msg = $this->translator->trans(
                'Invalid email/password combination',
                [],
                'Shop.Notifications.Error'
            );
            $this->errors['email'][] = $msg;
            $this->errors['password'][] = $msg;

            return false;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,9 +55,9 @@
     {
         if ($customer->id) {
             return $this->update($customer, $clearTextPassword, $newPassword, $passwordRequired);
-        } else {
-            return $this->create($customer, $clearTextPassword);
-        }
+        }
+
+        return $this->create($customer, $clearTextPassword);
     }
 
     private function update(Customer $customer, $clearTextPassword, $newPassword, $passwordRequired = true)
```
