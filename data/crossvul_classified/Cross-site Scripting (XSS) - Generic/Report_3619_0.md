# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3619_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3619_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 110-150 of the vulnerable file.


        if ( $type === 'xml' )
            return self::xmlEncode( $ret );
        else if ( $type === 'json' )
            return json_encode( $ret );
        else
            return self::textEncode( $ret );
    }

    /**
     * Encodes mixed value to string or comma seperated list of strings
     *
     * @param mixed $mix
     * @return string
     */
    public static function textEncode( $mix )
    {
        if ( is_array( $mix ) )
            return implode(',', array_map( array('ezjscAjaxContent', 'textEncode'), array_filter( $mix ) ) );

        return $mix;
    }

    /**
     * Function for encoding content object(s) or node(s) to simplified
     * json objects, xml or array hash
     *
     * @param mixed $obj
     * @param array $params
     * @param string $type
     * @return mixed
     */
    public static function nodeEncode( $obj, $params = array(), $type = 'json' )
    {
        if ( is_array( $obj ) )
        {
            $ret = array();
            foreach ( $obj as $ob )
            {
                $ret[] = self::simplify( $ob, $params );
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,7 +127,7 @@
         if ( is_array( $mix ) )
             return implode(',', array_map( array('ezjscAjaxContent', 'textEncode'), array_filter( $mix ) ) );
 
-        return $mix;
+        return htmlspecialchars( $mix );
     }
 
     /**
```
