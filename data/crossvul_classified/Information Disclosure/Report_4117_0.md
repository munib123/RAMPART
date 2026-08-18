# CrossVul Fix Pair: Observable Discrepancy in php
**Pair ID:** 4117_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4117_0`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```php
Lines 372-412 of the vulnerable file.

     * @param   array $params
     * @return  string
     */
    public function getUrl($route='', $params=array())
    {
        return Mage::helper('adminhtml')->getUrl($route, $params);
    }

    /**
     * Validate Secret Key
     *
     * @return bool
     */
    protected function _validateSecretKey()
    {
        if (is_array($this->_publicActions) && in_array($this->getRequest()->getActionName(), $this->_publicActions)) {
            return true;
        }

        if (!($secretKey = $this->getRequest()->getParam(Mage_Adminhtml_Model_Url::SECRET_KEY_PARAM_NAME, null))
            || $secretKey != Mage::getSingleton('adminhtml/url')->getSecretKey()) {
            return false;
        }
        return true;
    }

    /**
     * Validate password for current admin user
     *
     * @param string $password - current password
     *
     * @return mixed - returns true or array of errors
     */
    protected function _validateCurrentPassword($password)
    {
        $user = Mage::getSingleton('admin/session')->getUser();
        return $user->validateCurrentPassword($password);
    }

    /**
     * Check forced use form key for action
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,7 +389,7 @@
         }
 
         if (!($secretKey = $this->getRequest()->getParam(Mage_Adminhtml_Model_Url::SECRET_KEY_PARAM_NAME, null))
-            || $secretKey != Mage::getSingleton('adminhtml/url')->getSecretKey()) {
+            || !hash_equals(Mage::getSingleton('adminhtml/url')->getSecretKey(), $secretKey)) {
             return false;
         }
         return true;
```
