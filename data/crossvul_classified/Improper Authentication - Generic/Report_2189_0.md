# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 2189_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2189_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 189-229 of the vulnerable file.


    /**
     * Bind or rebind to the LDAP server.
     *
     * This function binds with the given DN and password to the
     * server. In case no connection has been made yet, it will be
     * started and STARTTLS issued if appropiate.
     *
     * The internal bind configuration is not being updated, so if you
     * call bind() without parameters, you can rebind with the
     * credentials provided at first connecting to the server.
     *
     * @param string $dn       DN for binding.
     * @param string $password Password for binding.
     *
     * @throws Horde_Ldap_Exception
     */
    public function bind($dn = null, $password = null)
    {
        /* Fetch current bind credentials. */
        if (empty($dn)) {
            $dn = $this->_config['binddn'];
        }
        if (empty($password)) {
            $password = $this->_config['bindpw'];
        }

        /* Connect first, if we haven't so far.  This will also bind
         * us to the server. */
        if (!$this->_link) {
            /* Store old credentials so we can revert them later, then
             * overwrite config with new bind credentials. */
            $olddn = $this->_config['binddn'];
            $oldpw = $this->_config['bindpw'];

            /* Overwrite bind credentials in config so
             * _connect() knows about them. */
            $this->_config['binddn'] = $dn;
            $this->_config['bindpw'] = $password;

            /* Try to connect with provided credentials. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,10 +206,10 @@
     public function bind($dn = null, $password = null)
     {
         /* Fetch current bind credentials. */
-        if (empty($dn)) {
+        if (is_null($dn)) {
             $dn = $this->_config['binddn'];
         }
-        if (empty($password)) {
+        if (is_null($password)) {
             $password = $this->_config['bindpw'];
         }
 
```
