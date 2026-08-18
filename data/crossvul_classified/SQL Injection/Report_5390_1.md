# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5390_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5390_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

    static function displayname() { return gt("Help"); }
    static function description() { return gt("Manage Exponent CMS help files."); }
    static function isSearchable() { return true; }

    function __construct($src=null, $params=array()) {
        parent::__construct($src,$params);
        // only set the system help version if it's not already set as a session variable
        if (!expSession::is_set('help-version')) {
            $version = help_version::getCurrentHelpVersion();
            if (empty($version)) {
                // there is no help version set to 'is_current'
                $hv = new help_version();
           	    $newversion = $hv->find('first','1');
                if (!empty($newversion)) {
                    $this->params['is_current'] = 1;
             	    $newversion->update($this->params);
                    $version = $newversion->version;
                }
            }
            if(!empty($params['version'])) {
                $version = isset($params['version']) ? (($params['version'] == 'current') ? $version : $params['version']) : $version;
            }
            expSession::set('help-version',$version);
        }
        $this->help_version = expSession::get('help-version');
	}

    /**
     * Display list of help documents
     */
	public function showall() {
	    expHistory::set('viewable', $this->params);
	    $hv = new help_version();
	    //$current_version = $hv->find('first', 'is_current=1');
	    $ref_version = $hv->find('first', 'version=\''.$this->help_version.'\'');

        // pagination parameter..hard coded for now.
		$where = $this->aggregateWhereClause();
	    $where .= 'AND help_version_id='.(empty($ref_version->id)?'0':$ref_version->id);
        if (empty($this->params['parent'])) {
            $where .= ' AND (parent=0 OR parent IS NULL)';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,7 @@
                 }
             }
             if(!empty($params['version'])) {
+                $params['version'] = expString::escape($params['version']);
                 $version = isset($params['version']) ? (($params['version'] == 'current') ? $version : $params['version']) : $version;
             }
             expSession::set('help-version',$version);
```
