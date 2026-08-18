# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in php
**Pair ID:** 2845_4
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2845_4`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```php
Lines 1-52 of the vulnerable file.

<?php

namespace Kanboard\Controller;

use Kanboard\Core\Controller\PageNotFoundException;

/**
 * Category Controller
 *
 * @package Kanboard\Controller
 * @author  Frederic Guillot
 */
class CategoryController extends BaseController
{
    /**
     * Get the category (common method between actions)
     *
     * @access private
     * @return array
     * @throws PageNotFoundException
     */
    private function getCategory()
    {
        $category = $this->categoryModel->getById($this->request->getIntegerParam('category_id'));

        if (empty($category)) {
            throw new PageNotFoundException();
        }

        return $category;
    }

    /**
     * List of categories for a given project
     *
     * @access public
     * @throws PageNotFoundException
     */
    public function index()
    {
        $project = $this->getProject();

        $this->response->html($this->helper->layout->project('category/index', array(
            'categories' => $this->categoryModel->getAll($project['id']),
            'project'    => $project,
            'title'      => t('Categories'),
        )));
    }

    /**
     * Show form to create new category
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,24 +12,6 @@
  */
 class CategoryController extends BaseController
 {
-    /**
-     * Get the category (common method between actions)
-     *
-     * @access private
-     * @return array
-     * @throws PageNotFoundException
-     */
-    private function getCategory()
-    {
-        $category = $this->categoryModel->getById($this->request->getIntegerParam('category_id'));
-
-        if (empty($category)) {
-            throw new PageNotFoundException();
-        }
-
-        return $category;
-    }
-
     /**
      * List of categories for a given project
      *
@@ -72,8 +54,9 @@
     public function save()
     {
         $project = $this->getProject();
+        $values = $this->request->getValues();
+        $values['project_id'] = $project['id'];
 
-        $values = $this->request->getValues();
         list($valid, $errors) = $this->categoryValidator->validateCreation($values);
 
         if ($valid) {
@@ -100,7 +83,7 @@
     public function edit(array $values = array(), array $errors = array())
     {
         $project = $this->getProject();
-        $category = $this->getCategory();
+        $category = $this->getCategory($project);
 
         $this->response->html($this->template->render('category/edit', array(
             'values'  => empty($values) ? $category : $values,
@@ -117,8 +100,12 @@
     public function update()
     {
         $project = $this->getProject();
+        $category = $this->getCategory($project);
 
         $values = $this->request->getValues();
+        $values['project_id'] = $project['id'];
+        $values['id'] = $category['id'];
+
         list($valid, $errors) = $this->categoryValidator->validateModification($values);
 
         if ($valid) {
@@ -141,7 +128,7 @@
     public function confirm()
     {
         $project = $this->getProject();
-        $category = $this->getCategory();
+        $category = $this->getCategory($project);
 
         $this->response->html($this->helper->layout->project('category/remove', array(
             'project'  => $project,
@@ -158,7 +145,7 @@
     {
         $this->checkCSRFParam();
         $project = $this->getProject();
-        $category = $this->getCategory();
+        $category = $this->getCategory($project);
 
         if ($this->categoryModel->remove($category['id'])) {
             $this->flash->success(t('Category removed successfully.'));
```
