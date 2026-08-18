# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2849_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2849_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 113-150 of the vulnerable file.

        }
    }            
 
    /**
     * Create output
     */
    function render($mode, &$renderer, $data) {
        if($mode == 'xhtml') {
            global $conf;
            $id = $data[0];
            $name = $data[1];
           
            //prepare for formating
            $link['target'] = $conf['target']['wiki'];
            $link['style']  = '';
            $link['pre']    = '';
            $link['suf']    = '';
            $link['more']   = '';
            $link['class']  = 'internallink';
            $link['url']    = DOKU_INTERNAL_LINK . $id;
            $link['name']   = ($name) ? $name : $id;
            $link['title']  = ($name) ? $name : $id;
            //add search string
            if($search){
                ($conf['userewrite']) ? $link['url'].='?s=' : $link['url'].='&amp;s=';
                $link['url'] .= urlencode($search);
            }
    
            //output formatted
            $renderer->doc .= $renderer->_formatLink($link);
        }
        return true;
    }
     
}
 
//Setup VIM: ex: et ts=4 enc=utf-8 :
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,8 +130,15 @@
             $link['more']   = '';
             $link['class']  = 'internallink';
             $link['url']    = DOKU_INTERNAL_LINK . $id;
-            $link['name']   = ($name) ? $name : $id;
-            $link['title']  = ($name) ? $name : $id;
+         
+            if(is_array($name)){
+               $link['name']   = (isset($name['title'])) ? hsc($name['title']) : hsc($id);
+               $link['title'] = $id;
+            } else{
+               $link['name']   = ($name) ? hsc($name) : hsc($id);
+               $link['title'] = ($name) ? $name : $id;
+            }
+
             //add search string
             if($search){
                 ($conf['userewrite']) ? $link['url'].='?s=' : $link['url'].='&amp;s=';
```
