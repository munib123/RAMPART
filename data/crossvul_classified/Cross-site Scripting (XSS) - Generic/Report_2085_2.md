# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2085_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2085_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 61-87 of the vulnerable file.


        return $view->loadScript(APPLICATION_PATH.'/boxes/'.$boxKey.'/render.php');
    }

    /**
     * Gets the header.
     *
     * @return string
     */
    public function getHeader()
    {
        $html = '<meta charset="utf-8">
                <title>'.$this->getTitle().'</title>
                <meta name="description" content="">';

        $html .= '<link href="'.$this->getStaticUrl('css/bootstrap.css').'" rel="stylesheet">
                <link href="'.$this->getStaticUrl('css/font-awesome.css').'" rel="stylesheet">
                <link href="'.$this->getStaticUrl('css/global.css').'" rel="stylesheet">
                <link href="'.$this->getStaticUrl('css/ui-lightness/jquery-ui.css').'" rel="stylesheet">
                <link href="'.$this->getStaticUrl('../application/modules/user/static/css/user.css').'" rel="stylesheet">
                <script src="'.$this->getStaticUrl('js/jquery.js').'"></script>
                <script src="'.$this->getStaticUrl('js/bootstrap.js').'"></script>
                <script src="'.$this->getStaticUrl('js/jquery-ui.js').'"></script>';
        return $html;
    }
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,10 +78,11 @@
                 <link href="'.$this->getStaticUrl('css/global.css').'" rel="stylesheet">
                 <link href="'.$this->getStaticUrl('css/ui-lightness/jquery-ui.css').'" rel="stylesheet">
                 <link href="'.$this->getStaticUrl('../application/modules/user/static/css/user.css').'" rel="stylesheet">
-                <script src="'.$this->getStaticUrl('js/jquery.js').'"></script>
-                <script src="'.$this->getStaticUrl('js/bootstrap.js').'"></script>
-                <script src="'.$this->getStaticUrl('js/jquery-ui.js').'"></script>';
+                <script type="text/javascript" src="'.$this->getStaticUrl('js/jquery.js').'"></script>
+                <script type="text/javascript" src="'.$this->getStaticUrl('js/bootstrap.js').'"></script>
+                <script type="text/javascript" src="'.$this->getStaticUrl('js/jquery-ui.js').'"></script>
+                <script type="text/javascript" src="'.$this->getStaticUrl('js/ckeditor/ckeditor.js').'"></script>
+                <script type="text/javascript" src="'.$this->getStaticUrl('js/ilch.js').'"></script>';
         return $html;
     }
 }
-
```
