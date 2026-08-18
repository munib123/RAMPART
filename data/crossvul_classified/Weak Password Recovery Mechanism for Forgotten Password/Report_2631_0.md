# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 2631_0
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2631_0`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.


        return $this->response->html($this->helper->layout->user('user_credential/password', array(
            'values' => $values + array('id' => $user['id']),
            'errors' => $errors,
            'user' => $user,
        )));
    }

    /**
     * Save new password
     *
     * @throws \Kanboard\Core\Controller\AccessForbiddenException
     * @throws \Kanboard\Core\Controller\PageNotFoundException
     */
    public function savePassword()
    {
        $user = $this->getUser();
        $values = $this->request->getValues();

        list($valid, $errors) = $this->userValidator->validatePasswordModification($values);

        if ($valid) {
            if ($this->userModel->update($values)) {
                $this->flash->success(t('Password modified successfully.'));
                $this->userLockingModel->resetFailedLogin($user['username']);
                $this->response->redirect($this->helper->url->to('UserViewController', 'show', array('user_id' => $user['id'])), true);
                return;
            } else {
                $this->flash->failure(t('Unable to change the password.'));
            }
        }

        $this->changePassword($values, $errors);
    }

    /**
     * Display a form to edit authentication
     *
     * @access public
     * @param array $values
     * @param array $errors
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,10 @@
         $values = $this->request->getValues();
 
         list($valid, $errors) = $this->userValidator->validatePasswordModification($values);
+
+        if (! $this->userSession->isAdmin()) {
+            $values['id'] = $this->userSession->getId();
+        }
 
         if ($valid) {
             if ($this->userModel->update($values)) {
```
