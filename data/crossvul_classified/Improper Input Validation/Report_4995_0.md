# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4995_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4995_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 153-193 of the vulnerable file.

    public function getTemplateName()
    {
        $request = $this->viewRenderer->Action()->Request();
        $dispatcher = $this->viewRenderer->Front()->Dispatcher();

        $moduleName = $dispatcher->formatModuleName($request->getModuleName());
        $controllerName = $dispatcher->formatControllerName($request->getControllerName());

        $inflector = new Zend_Filter_Inflector($this->target);
        $inflector->setRules($this->filterRules);
        $inflector->setThrowTargetExceptionsOn(false);

        $fileNames = (array) $request->getParam('file', $this->defaultFile);

        if (empty($fileNames)) {
            $fileNames = $request->getParam('f');
            $fileNames = explode('|', $fileNames);
        }

        $templateNames = array();

        foreach ($fileNames as $fileName) {
            // if string starts with "m/" replace with "model/"
            $fileName = preg_replace('/^m\//', 'model/', $fileName);
            $fileName = preg_replace('/^c\//', 'controller/', $fileName);
            $fileName = preg_replace('/^v\//', 'view/', $fileName);

            $fileName = ltrim(dirname($fileName) . '/' . basename($fileName, '.js'), '/.');

            if (empty($fileName)) {
                continue;
            }

            $templateNames[] = $inflector->filter(array(
                'module'     => $moduleName,
                'controller' => $controllerName,
                'file'       => $fileName)
            );
        }

        $count = count($templateNames);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,28 +170,35 @@
         }
 
         $templateNames = array();
-
         foreach ($fileNames as $fileName) {
+            // Remove unwanted characters
+            $fileName = preg_replace('/[^a-z0-9\/_-]/i', '', $fileName);
+
+            // Replace multiple forward slashes
+            $fileName = preg_replace('#/+#', '/', $fileName);
+
+            // Remove leading and trailing forward slash
+            $fileName = trim($fileName, '/');
+
             // if string starts with "m/" replace with "model/"
             $fileName = preg_replace('/^m\//', 'model/', $fileName);
             $fileName = preg_replace('/^c\//', 'controller/', $fileName);
             $fileName = preg_replace('/^v\//', 'view/', $fileName);
 
-            $fileName = ltrim(dirname($fileName) . '/' . basename($fileName, '.js'), '/.');
-
             if (empty($fileName)) {
                 continue;
             }
 
-            $templateNames[] = $inflector->filter(array(
+            $fileName = $inflector->filter(array(
                 'module'     => $moduleName,
                 'controller' => $controllerName,
-                'file'       => $fileName)
-            );
+                'file'       => $fileName
+            ));
+
+            $templateNames[]  = $fileName;
         }
 
         $count = count($templateNames);
-
         if ($count === 0) {
             return null;
         } elseif ($count === 1) {
```
