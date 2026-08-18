# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3559_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3559_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.

        return $this->_logFilename;
    }

    protected function _format($part, $text)
    {
        return "** $part **\n$text\n-- $part --\n\n";
    }

    public function render($ignoreCli = false)
    {
        if (!$ignoreCli && php_sapi_name() == 'cli') {
            $this->log();
            file_put_contents('php://stderr', $this->getException()->__toString()."\n");
            exit(1);
        }

        $view = Kwf_Debug::getView();
        $view->exception = $this->getException();
        $view->message = $this->getException()->getMessage();
        $view->requestUri = isset($_SERVER['REQUEST_URI']) ?
            $_SERVER['REQUEST_URI'] : '' ;
        $view->debug = Kwf_Exception::isDebug();
        $header = $this->getHeader();
        $template = $this->getTemplate();
        $template = strtolower(Zend_Filter::filterStatic($template, 'Word_CamelCaseToDash').'.tpl');
        $this->log();

        if (!headers_sent()) {
            header($header);
            header('Content-Type: text/html; charset=utf-8');
        }

        try {
            echo $view->render($template);
        } catch (Exception $e) {
            echo '<pre>';
            echo $this->__toString();
            echo "\n\n\nError happened while handling exception:";
            echo $e->__toString();
            echo '</pre>';
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
         $view->exception = $this->getException();
         $view->message = $this->getException()->getMessage();
         $view->requestUri = isset($_SERVER['REQUEST_URI']) ?
-            $_SERVER['REQUEST_URI'] : '' ;
+            htmlspecialchars($_SERVER['REQUEST_URI']) : '' ;
         $view->debug = Kwf_Exception::isDebug();
         $header = $this->getHeader();
         $template = $this->getTemplate();
```
