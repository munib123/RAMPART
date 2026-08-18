# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_7
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_7`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 48-80 of the vulnerable file.

                $this->flash->success(t('Project updated successfully.'));
                return $this->response->redirect($this->helper->url->to('ProjectEditController', 'show', array('project_id' => $project['id'])), true);
            } else {
                $this->flash->failure(t('Unable to update this project.'));
            }
        }

        return $this->show($values, $errors);
    }

    /**
     * Prepare form values
     *
     * @access private
     * @param  array  $project
     * @param  array  $values
     * @return array
     */
    private function prepareValues(array $project, array $values)
    {
        if (isset($values['is_private'])) {
            if (! $this->helper->user->hasProjectAccess('ProjectCreationController', 'create', $project['id'])) {
                unset($values['is_private']);
            }
        } elseif ($project['is_private'] == 1 && ! isset($values['is_private'])) {
            if ($this->helper->user->hasProjectAccess('ProjectCreationController', 'create', $project['id'])) {
                $values += array('is_private' => 0);
            }
        }

        return $values;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,8 @@
      */
     private function prepareValues(array $project, array $values)
     {
+        $values['id'] = $project['id'];
+
         if (isset($values['is_private'])) {
             if (! $this->helper->user->hasProjectAccess('ProjectCreationController', 'create', $project['id'])) {
                 unset($values['is_private']);
```
