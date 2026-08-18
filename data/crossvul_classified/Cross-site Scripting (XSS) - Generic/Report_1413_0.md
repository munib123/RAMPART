# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1413_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1413_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 152-192 of the vulnerable file.

     * Set Formatter
     *
     * @param  FormatterInterface $formatter
     * @return $this
     */
    public function setFormatter(FormatterInterface $formatter)
    {
        $this->formatter = $formatter;
        return $this;
    }

    /**
     * Execute a PicoDb query
     *
     * @access public
     * @return array
     */
    public function executeQuery()
    {
        if ($this->query !== null) {
            $this->query
                ->offset($this->offset)
                ->limit($this->limit)
                ->orderBy($this->order, $this->direction);

            if ($this->formatter !== null) {
                return $this->formatter->withQuery($this->query)->format();
            } else {
                return $this->query->findAll();
            }
        }

        return array();
    }

    /**
     * Set url parameters
     *
     * @access public
     * @param  string      $controller
     * @param  string      $action
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,10 +169,16 @@
     public function executeQuery()
     {
         if ($this->query !== null) {
+
             $this->query
                 ->offset($this->offset)
-                ->limit($this->limit)
-                ->orderBy($this->order, $this->direction);
+                ->limit($this->limit);
+
+            if (preg_match('/^[a-zA-Z0-9._]+$/', $this->order)) {
+                $this->query->orderBy($this->order, $this->direction);
+            } else {
+                $this->order = '';
+            }
 
             if ($this->formatter !== null) {
                 return $this->formatter->withQuery($this->query)->format();
```
