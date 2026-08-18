# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3323_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3323_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 492-513 of the vulnerable file.

            'quarantine'      => '..' . DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR . 'elfinder' . DIRECTORY_SEPARATOR . '.quarantine',
            'acceptedName'    => '/^[^\.].*$/',
            // 'acceptedName'    => '/^[\W]*$/',
            // 'acceptedName'    => 'validName',
            'utf8fix'         => false,
//            'statOwner'       => true,
            'attributes'      => array(
                array(
                    'pattern' => '/^\/\./', // dot files are hidden
                    'read'    => false,
                    'write'   => false,
                    'hidden'  => true,
                    'locked'  => true
                )
            )
        )
    )
);

//header('Access-Control-Allow-Origin: *');
$connector = new elFinderConnector(new elFinderExponent($opts), true);
$connector->run();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -509,5 +509,5 @@
 );
 
 //header('Access-Control-Allow-Origin: *');
-$connector = new elFinderConnector(new elFinderExponent($opts), true);
+$connector = new elFinderConnector(new elFinderExponent($opts));
 $connector->run();
```
