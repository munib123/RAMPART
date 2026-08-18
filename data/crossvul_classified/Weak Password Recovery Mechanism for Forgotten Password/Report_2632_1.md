# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 2632_1
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2632_1`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 30-69 of the vulnerable file.


        return $this->response->html($this->helper->layout->user('user_modification/show', array(
            'values' => $values,
            'errors' => $errors,
            'user' => $user,
            'timezones' => $this->timezoneModel->getTimezones(true),
            'languages' => $this->languageModel->getLanguages(true),
            'roles' => $this->role->getApplicationRoles(),
        )));
    }

    /**
     * Save user information
     */
    public function save()
    {
        $user = $this->getUser();
        $values = $this->request->getValues();

        if (! $this->userSession->isAdmin()) {
            if (isset($values['role'])) {
                unset($values['role']);
            }
        }

        list($valid, $errors) = $this->userValidator->validateModification($values);

        if ($valid) {
            if ($this->userModel->update($values)) {
                $this->flash->success(t('User updated successfully.'));
                $this->response->redirect($this->helper->url->to('UserViewController', 'show', array('user_id' => $user['id'])), true);
                return;
            } else {
                $this->flash->failure(t('Unable to update this user.'));
            }
        }

        $this->show($values, $errors);
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,9 +47,14 @@
         $values = $this->request->getValues();
 
         if (! $this->userSession->isAdmin()) {
-            if (isset($values['role'])) {
-                unset($values['role']);
-            }
+            $values = array(
+                'id' => $this->userSession->getId(),
+                'username' => isset($values['username']) ? $values['username'] : '',
+                'name' => isset($values['name']) ? $values['name'] : '',
+                'email' => isset($values['email']) ? $values['email'] : '',
+                'timezone' => isset($values['timezone']) ? $values['timezone'] : '',
+                'language' => isset($values['language']) ? $values['language'] : '',
+            );
         }
 
         list($valid, $errors) = $this->userValidator->validateModification($values);
```
