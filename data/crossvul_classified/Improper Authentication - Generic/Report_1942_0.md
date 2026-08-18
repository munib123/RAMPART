# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 1942_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1942_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 245-285 of the vulnerable file.

    /**
     * Delete cookie
     * As of version 1.5 don't call this function, use Customer::logout() or Employee::logout() instead;.
     */
    public function logout()
    {
        $this->deleteSession();
        $this->_content = [];
        $this->encryptAndSetCookie();
        unset($_COOKIE[$this->_name]);
        $this->_modified = true;
    }

    /**
     * Soft logout, delete everything links to the customer
     * but leave there affiliate's informations.
     * As of version 1.5 don't call this function, use Customer::mylogout() instead;.
     */
    public function mylogout()
    {
        unset(
            $this->_content['id_customer'],
            $this->_content['id_guest'],
            $this->_content['is_guest'],
            $this->_content['id_connections'],
            $this->_content['customer_lastname'],
            $this->_content['customer_firstname'],
            $this->_content['passwd'],
            $this->_content['logged'],
            $this->_content['email'],
            $this->_content['id_cart'],
            $this->_content['id_address_invoice'],
            $this->_content['id_address_delivery']
        );
        $this->_modified = true;
    }

    public function makeNewLog()
    {
        unset(
            $this->_content['id_customer'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,6 +262,7 @@
      */
     public function mylogout()
     {
+        $this->deleteSession();
         unset(
             $this->_content['id_customer'],
             $this->_content['id_guest'],
@@ -514,7 +515,7 @@
      */
     public function isSessionAlive()
     {
-        if (!isset($this->session_id, $this->session_token)) {
+        if (!isset($this->session_id) || !isset($this->session_token)) {
             return false;
         }
 
```
