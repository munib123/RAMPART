# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 2631_1
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2631_1`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 99-128 of the vulnerable file.

        );
    }

    /**
     * Validate password modification
     *
     * @access public
     * @param  array   $values           Form values
     * @return array   $valid, $errors   [0] = Success or not, [1] = List of errors
     */
    public function validatePasswordModification(array $values)
    {
        $rules = array(
            new Validators\Required('id', t('The user id is required')),
            new Validators\Required('current_password', t('The current password is required')),
        );

        $v = new Validator($values, array_merge($rules, $this->commonPasswordValidationRules()));

        if ($v->execute()) {
            if ($this->authenticationManager->passwordAuthentication($this->userSession->getUsername(), $values['current_password'], false)) {
                return array(true, array());
            } else {
                return array(false, array('current_password' => array(t('Wrong password'))));
            }
        }

        return array(false, $v->getErrors());
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,6 +116,10 @@
         $v = new Validator($values, array_merge($rules, $this->commonPasswordValidationRules()));
 
         if ($v->execute()) {
+            if (! $this->userSession->isAdmin() && $values['id'] != $this->userSession->getId()) {
+                return array(false, array('current_password' => array('Invalid User ID')));
+            }
+
             if ($this->authenticationManager->passwordAuthentication($this->userSession->getUsername(), $values['current_password'], false)) {
                 return array(true, array());
             } else {
```
