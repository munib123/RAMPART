# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5570_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5570_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 103-132 of the vulnerable file.

        }

        if ($this->repository->isUsed($language)) {
            $this->_helper->flashMessenger->addMessage(getGS('Language is in use and cannot be removed.'));
            $this->_helper->redirector('index', 'languages', 'admin');
        }

        Localizer::DeleteLanguageFiles($language->getCode());
        $this->repository->delete($language->getId());
        $this->_helper->flashMessenger->addMessage(getGS('Language removed.'));
        $this->_helper->redirector('index', 'languages', 'admin');
    }

    /**
     * Get language
     *
     * @return Newscoop\Entity\Language
     */
    private function getLanguage()
    {
        $id = $this->getRequest()->getParam('language');
        $language = $this->repository->find($id);
        if (empty($language)) {
            $this->_helper->flashMessenger->addMessage(getGS('Language not found.'));
            $this->_forward('index');
        }

        return $language;
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,11 +120,16 @@
      */
     private function getLanguage()
     {
-        $id = $this->getRequest()->getParam('language');
-        $language = $this->repository->find($id);
+        $id = (int) $this->getRequest()->getParam('language');
+        if (!$id) {
+            $this->_helper->flashMessenger(array('error', getGS('Language id not specified')));
+            $this->_helper->redirector('index');
+        }
+
+        $language = $this->repository->findOneBy(array('id' => $id));
         if (empty($language)) {
             $this->_helper->flashMessenger->addMessage(getGS('Language not found.'));
-            $this->_forward('index');
+            $this->_helper->redirector('index');
         }
 
         return $language;
```
