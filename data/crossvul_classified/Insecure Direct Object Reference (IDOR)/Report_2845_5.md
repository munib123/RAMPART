# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_5
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_5`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 44-84 of the vulnerable file.

        if (empty($values)) {
            $values = array('project_id' => $project['id']);
        }

        $this->response->html($this->template->render('column/create', array(
            'values' => $values,
            'errors' => $errors,
            'project' => $project,
        )));
    }

    /**
     * Validate and add a new column
     *
     * @access public
     */
    public function save()
    {
        $project = $this->getProject();
        $values = $this->request->getValues() + array('hide_in_dashboard' => 0);

        list($valid, $errors) = $this->columnValidator->validateCreation($values);

        if ($valid) {
            $result = $this->columnModel->create(
                $project['id'],
                $values['title'],
                $values['task_limit'],
                $values['description'],
                $values['hide_in_dashboard']
            );

            if ($result !== false) {
                $this->flash->success(t('Column created successfully.'));
                $this->response->redirect($this->helper->url->to('ColumnController', 'index', array('project_id' => $project['id'])), true);
                return;
            } else {
                $errors['title'] = array(t('Another column with the same name exists in the project'));
            }
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,7 @@
     {
         $project = $this->getProject();
         $values = $this->request->getValues() + array('hide_in_dashboard' => 0);
+        $values['project_id'] = $project['id'];
 
         list($valid, $errors) = $this->columnValidator->validateCreation($values);
 
@@ -95,7 +96,7 @@
     public function edit(array $values = array(), array $errors = array())
     {
         $project = $this->getProject();
-        $column = $this->columnModel->getById($this->request->getIntegerParam('column_id'));
+        $column = $this->getColumn($project);
 
         $this->response->html($this->helper->layout->project('column/edit', array(
             'errors' => $errors,
@@ -113,7 +114,11 @@
     public function update()
     {
         $project = $this->getProject();
+        $column = $this->getColumn($project);
+
         $values = $this->request->getValues() + array('hide_in_dashboard' => 0);
+        $values['project_id'] = $project['id'];
+        $values['id'] = $column['id'];
 
         list($valid, $errors) = $this->columnValidator->validateModification($values);
 
@@ -164,9 +169,10 @@
     public function confirm()
     {
         $project = $this->getProject();
+        $column = $this->getColumn($project);
 
         $this->response->html($this->helper->layout->project('column/remove', array(
-            'column' => $this->columnModel->getById($this->request->getIntegerParam('column_id')),
+            'column' => $column,
             'project' => $project,
         )));
     }
@@ -178,11 +184,11 @@
      */
     public function remove()
     {
+        $this->checkCSRFParam();
         $project = $this->getProject();
-        $this->checkCSRFParam();
-        $column_id = $this->request->getIntegerParam('column_id');
+        $column = $this->getColumn($project);
 
-        if ($this->columnModel->remove($column_id)) {
+        if ($this->columnModel->remove($column['id'])) {
             $this->flash->success(t('Column removed successfully.'));
         } else {
             $this->flash->failure(t('Unable to remove this column.'));
```
