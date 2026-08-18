# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2385_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2385_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 147-187 of the vulnerable file.

    
    /**
     * CmsInput::cleanEncode()
     * 
     * @param mixed $str
     * @return
     */
    public function cleanEncode($str)
    {
        return $this->encode($this->xssClean($str));
    }
    
    /**
     * CmsInput::stripClean()
     * 
     * @param mixed $str
     * @return
     */
    public function stripClean($str)
    {
        return $this->xssClean($this->stripTags($str));
    }
    
    /**
     * CmsInput::encode()
     * 
     * @param mixed $str
     * @return
     */
    public function encode($str)
    {
        if(is_array($str))
        {
            foreach($str AS $k=>$v)
                $str[$k]=$this->encode($v);
            return $str;
        }
        return CHtml::encode($str);
    }
    
    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,7 +164,7 @@
      */
     public function stripClean($str)
     {
-        return $this->xssClean($this->stripTags($str));
+        return $this->stripTags($this->xssClean($str));
     }
     
     /**
```
