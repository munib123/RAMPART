# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4995_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4995_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 191-231 of the vulnerable file.

        ));
        $inflector->setThrowTargetExceptionsOn(false);

        $fileNames = (array) $request->getParam('file');

        if (empty($fileNames)) {
            $fileNames = $request->getParam('f', array());
            $fileNames = explode('|', $fileNames);
        }

        if (empty($fileNames)) {
            return;
        }

        $this->Response()->setHeader('Content-Type', 'application/javascript; charset=utf-8', true);
        $template = 'snippet:string:';

        $this->View()->Engine()->setCompileId($this->View()->Engine()->getCompileId() . '_' . $this->Request()->getControllerName());

        foreach ($fileNames as $fileName) {
            // if string starts with "m/" replace with "model/"
            $fileName = preg_replace('/^m\//', 'model/', $fileName);
            $fileName = preg_replace('/^c\//', 'controller/', $fileName);
            $fileName = preg_replace('/^v\//', 'view/', $fileName);

            $fileName = ltrim(dirname($fileName) . '/' . basename($fileName, '.js'), '/.');
            if (empty($fileName)) {
                continue;
            }
            $templateBase = $inflector->filter(array(
                'module' => $moduleName,
                'controller' => $controllerName,
                'file' => $fileName)
            );

            $templateExtend = $inflector->filter(array(
                'module' => $moduleName,
                'controller' => $this->Request()->getControllerName(),
                'file' => $fileName)
            );
            if ($this->View()->templateExists($templateBase)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -208,26 +208,36 @@
         $this->View()->Engine()->setCompileId($this->View()->Engine()->getCompileId() . '_' . $this->Request()->getControllerName());
 
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
             if (empty($fileName)) {
                 continue;
             }
+
             $templateBase = $inflector->filter(array(
-                'module' => $moduleName,
+                'module'     => $moduleName,
                 'controller' => $controllerName,
-                'file' => $fileName)
-            );
+                'file'       => $fileName
+            ));
 
             $templateExtend = $inflector->filter(array(
-                'module' => $moduleName,
+                'module'     => $moduleName,
                 'controller' => $this->Request()->getControllerName(),
-                'file' => $fileName)
-            );
+                'file'       => $fileName
+            ));
+
             if ($this->View()->templateExists($templateBase)) {
                 $template .= '{include file="' . $templateBase. '"}' . "\n";
             }
```
