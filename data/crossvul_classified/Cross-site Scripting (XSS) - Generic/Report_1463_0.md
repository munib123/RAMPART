# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1463_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1463_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 350-393 of the vulnerable file.

     * It may be overridden if required, e.g. to implement your own action-handling.
     * By default, the method to be called is set up out of the action-param passed.
     * Example: The action requested is names "newPage". Therefore, the framework tries to
     * call actionNewPage(). If no method matching the schema is found, an exception is being thrown.
     * The actions' output is saved back to self::strOutput and, is returned in addition.
     * Returning the content is only implemented to remain backwards compatible with older implementations.
     * Since Kajona 4.0, the check on declarative permissions via annotations is supported.
     * Therefore the list of permissions, named after the "permissions" annotation are validated against
     * the module currently loaded.
     *
     * @param string $strAction
     *
     * @see class_rights::validatePermissionString
     *
     * @throws class_exception
     * @return string
     * @since 3.4
     */
    public function action($strAction = "") {

        if($strAction == "") {
            $strAction = $this->getAction();
        }
        else {
            $this->setAction($strAction);
        }

        //search for the matching method - build method name
        $strMethodName = "action" . uniStrtoupper($strAction[0]) . uniSubstr($strAction, 1);

        if(method_exists($this, $strMethodName)) {

            //validate the permissions required to call this method, the xml-part is validated afterwards
            $objAnnotations = new class_reflection(get_class($this));

            $strPermissions = $objAnnotations->getMethodAnnotationValue($strMethodName, "@permissions");
            if($strPermissions !== false) {

                if(validateSystemid($this->getSystemid()) && class_objectfactory::getInstance()->getObject($this->getSystemid()) != null) {
                    $objObjectToCheck = class_objectfactory::getInstance()->getObject($this->getSystemid());
                }
                else {
                    $objObjectToCheck = $this->getObjModule();
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -367,12 +367,11 @@
      */
     public function action($strAction = "") {
 
-        if($strAction == "") {
-            $strAction = $this->getAction();
-        }
-        else {
+        if($strAction != "") {
             $this->setAction($strAction);
         }
+
+        $strAction = $this->getAction();
 
         //search for the matching method - build method name
         $strMethodName = "action" . uniStrtoupper($strAction[0]) . uniSubstr($strAction, 1);
```
