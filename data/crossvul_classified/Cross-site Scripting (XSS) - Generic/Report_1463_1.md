# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1463_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1463_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 103-143 of the vulnerable file.


        //Generating all the required objects. For this we use our cool cool carrier-object
        //take care of loading just the necessary objects
        $objCarrier = class_carrier::getInstance();

        $this->objConfig = $objCarrier->getObjConfig();
        $this->objSession = $objCarrier->getObjSession();
        $this->objLang = $objCarrier->getObjLang();
        $this->objTemplate = $objCarrier->getObjTemplate();

        //Setting SystemID
        if($strSystemid == "") {
            $this->setSystemid(class_carrier::getInstance()->getParam("systemid"));
        }
        else {
            $this->setSystemid($strSystemid);
        }


        //And keep the action
        $this->strAction = $this->getParam("action");
        //in most cases, the list is the default action if no other action was passed
        if($this->strAction == "") {
            $this->strAction = "list";
        }

        //try to load the current module-name and the moduleId by reflection
        $objReflection = new class_reflection($this);
        if(!isset($this->arrModule["modul"])) {
            $arrAnnotationValues = $objReflection->getAnnotationValuesFromClass(self::STR_MODULE_ANNOTATION);
            if(count($arrAnnotationValues) > 0)
                $this->setArrModuleEntry("modul", trim($arrAnnotationValues[0]));
        }

        if(!isset($this->arrModule["moduleId"])) {
            $arrAnnotationValues = $objReflection->getAnnotationValuesFromClass(self::STR_MODULEID_ANNOTATION);
            if(count($arrAnnotationValues) > 0)
                $this->setArrModuleEntry("moduleId", constant(trim($arrAnnotationValues[0])));
        }

        $this->strLangBase = $this->getArrModule("modul");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,10 +120,10 @@
 
 
         //And keep the action
-        $this->strAction = $this->getParam("action");
+        $this->setAction($this->getParam("action"));
         //in most cases, the list is the default action if no other action was passed
-        if($this->strAction == "") {
-            $this->strAction = "list";
+        if($this->getAction() == "") {
+            $this->setAction("list");
         }
 
         //try to load the current module-name and the moduleId by reflection
@@ -197,7 +197,7 @@
      * @return void
      */
     public final function setAction($strAction) {
-        $this->strAction = $strAction;
+        $this->strAction = htmlspecialchars(trim($strAction), ENT_QUOTES, "UTF-8", false);
     }
 
 
```
