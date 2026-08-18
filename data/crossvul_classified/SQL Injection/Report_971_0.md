# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 971_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `971_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

require_once dirname(__FILE__) . '/../../../objects/user.php';

class AuditTable extends ObjectYPT {

    protected $id, $method, $class, $statement, $formats, $values, $ip, $users_id;
    
    static function getSearchFieldsNames() {
        return array('method','class','statement','ip','a.created', 'user');
    }

    static function getTableName() {
        return 'audit';
    }
        
    
    function audit($method, $class, $statement, $formats, $values, $users_id) {
        $this->method = $method;
        $this->class = $class;
        $this->statement = substr(str_replace("'", "", $statement),0,1000)."n";
        $this->formats = $formats;
        $this->values = $values;
        $this->ip = getRealIpAddr();
        $this->users_id = empty($users_id)?"NULL":$users_id;
        return $this->save();
    }
    
    static function getTotal() {
        //will receive
        //current=1&rowCount=10&sort[sender]=asc&searchPhrase=
        global $global;
        $sql = "SELECT a.id FROM  " . static::getTableName() . " a LEFT JOIN users u ON u.id = users_id  WHERE 1=1  ";
        $sql .= self::getSqlSearchFromPost();
        //echo $sql;
        $res = sqlDAL::readSql($sql); 
        $countRow = sqlDAL::num_rows($res);
        sqlDAL::close($res);
        return $countRow;
    }    

    static function getAll() {
        global $global;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
         $this->class = $class;
         $this->statement = substr(str_replace("'", "", $statement),0,1000)."n";
         $this->formats = $formats;
-        $this->values = $values;
+        $this->values = str_replace(array("'","\\"), array("",""), $values);
         $this->ip = getRealIpAddr();
         $this->users_id = empty($users_id)?"NULL":$users_id;
         return $this->save();
```
