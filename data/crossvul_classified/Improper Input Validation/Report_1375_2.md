# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1375_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1375_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 177-217 of the vulnerable file.

    }

    /**
     * @param DOMDocument $objDoc
     * @param int $pos
     * @return DOMNode|null
     */
    public function locateSignature($objDoc, $pos=0)
    {
        if ($objDoc instanceof DOMDocument) {
            $doc = $objDoc;
        } else {
            $doc = $objDoc->ownerDocument;
        }
        if ($doc) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = ".//secdsig:Signature";
            $nodeset = $xpath->query($query, $objDoc);
            $this->sigNode = $nodeset->item($pos);
            return $this->sigNode;
        }
        return null;
    }

    /**
     * @param string $name
     * @param null|string $value
     * @return DOMElement
     */
    public function createNewSignNode($name, $value=null)
    {
        $doc = $this->sigNode->ownerDocument;
        if (! is_null($value)) {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.$name, $value);
        } else {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.$name);
        }
        return $node;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,11 @@
             $query = ".//secdsig:Signature";
             $nodeset = $xpath->query($query, $objDoc);
             $this->sigNode = $nodeset->item($pos);
+            $query = "./secdsig:SignedInfo";
+            $nodeset = $xpath->query($query, $this->sigNode);
+            if ($nodeset->length > 1) {
+                throw new Exception("Invalid structure - Too many SignedInfo elements found");
+            }
             return $this->sigNode;
         }
         return null;
@@ -303,6 +308,9 @@
             $xpath = $this->getXPathObj();
             $query = "./secdsig:SignedInfo";
             $nodeset = $xpath->query($query, $this->sigNode);
+            if ($nodeset->length > 1) {
+                throw new Exception("Invalid structure - Too many SignedInfo elements found");
+            }
             if ($signInfoNode = $nodeset->item(0)) {
                 $query = "./secdsig:CanonicalizationMethod";
                 $nodeset = $xpath->query($query, $signInfoNode);
@@ -440,7 +448,7 @@
                         if ($node->localName == 'XPath') {
                             $arXPath = array();
                             $arXPath['query'] = '(.//. | .//@* | .//namespace::*)['.$node->nodeValue.']';
-                            $arXpath['namespaces'] = array();
+                            $arXPath['namespaces'] = array();
                             $nslist = $xpath->query('./namespace::*', $node);
                             foreach ($nslist AS $nsnode) {
                                 if ($nsnode->localName != "xml") {
@@ -554,7 +562,7 @@
         $refids = array();
 
         $xpath = $this->getXPathObj();
-        $query = "./secdsig:SignedInfo/secdsig:Reference";
+        $query = "./secdsig:SignedInfo[1]/secdsig:Reference";
         $nodeset = $xpath->query($query, $this->sigNode);
         if ($nodeset->length == 0) {
             throw new Exception("Reference nodes not found");
@@ -578,7 +586,7 @@
             }
         }
         $xpath = $this->getXPathObj();
-        $query = "./secdsig:SignedInfo/secdsig:Reference";
+        $query = "./secdsig:SignedInfo[1]/secdsig:Reference";
         $nodeset = $xpath->query($query, $this->sigNode);
         if ($nodeset->length == 0) {
             throw new Exception("Reference nodes not found");
```
