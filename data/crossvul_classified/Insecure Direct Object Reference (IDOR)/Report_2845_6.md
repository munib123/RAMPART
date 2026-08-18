# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_6
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_6`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 42-82 of the vulnerable file.

    {
        $project = $this->getProject();

        $this->response->html($this->template->render('custom_filter/create', array(
            'values' => $values + array('project_id' => $project['id']),
            'errors' => $errors,
            'project' => $project,
        )));
    }

    /**
     * Save a new custom filter
     *
     * @access public
     */
    public function save()
    {
        $project = $this->getProject();

        $values = $this->request->getValues();
        $values['user_id'] = $this->userSession->getId();

        list($valid, $errors) = $this->customFilterValidator->validateCreation($values);

        if ($valid) {
            if ($this->customFilterModel->create($values) !== false) {
                $this->flash->success(t('Your custom filter have been created successfully.'));
                $this->response->redirect($this->helper->url->to('CustomFilterController', 'index', array('project_id' => $project['id'])), true);
                return;
            } else {
                $this->flash->failure(t('Unable to create your custom filter.'));
            }
        }

        $this->create($values, $errors);
    }

    /**
     * Confirmation dialog before removing a custom filter
     *
     * @access public
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,6 +59,7 @@
         $project = $this->getProject();
 
         $values = $this->request->getValues();
+        $values['project_id'] = $project['id'];
         $values['user_id'] = $this->userSession->getId();
 
         list($valid, $errors) = $this->customFilterValidator->validateCreation($values);
@@ -84,7 +85,7 @@
     public function confirm()
     {
         $project = $this->getProject();
-        $filter = $this->customFilterModel->getById($this->request->getIntegerParam('filter_id'));
+        $filter = $this->getCustomFilter($project);
 
         $this->response->html($this->helper->layout->project('custom_filter/remove', array(
             'project' => $project,
@@ -102,7 +103,7 @@
     {
         $this->checkCSRFParam();
         $project = $this->getProject();
-        $filter = $this->customFilterModel->getById($this->request->getIntegerParam('filter_id'));
+        $filter = $this->getCustomFilter($project);
 
         $this->checkPermission($project, $filter);
 
@@ -153,6 +154,8 @@
         $this->checkPermission($project, $filter);
 
         $values = $this->request->getValues();
+        $values['id'] = $filter['id'];
+        $values['project_id'] = $project['id'];
 
         if (! isset($values['is_shared'])) {
             $values += array('is_shared' => 0);
```
