# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3821_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3821_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 197-237 of the vulnerable file.

        }

        if (isset($value[0])) {
          $s .= ($s?' ':'') . $cssid . ':' . $value . ';';
        }
      }
    }
    return $s;
  }

  /* Take a node and return allowed attributes and check values */
  private function wash_attribs($node)
  {
    $t = '';
    $washed;

    foreach ($node->attributes as $key => $plop) {
      $key = strtolower($key);
      $value = $node->getAttribute($key);
      if (isset($this->_html_attribs[$key]) ||
         ($key == 'href' && !preg_match('!^javascript!i', $value)
           && preg_match('!^([a-z][a-z0-9.+-]+:|//|#).+!i', $value))
      ) {
        $t .= ' ' . $key . '="' . htmlspecialchars($value, ENT_QUOTES) . '"';
      }
      else if ($key == 'style' && ($style = $this->wash_style($value))) {
        $quot = strpos($style, '"') !== false ? "'" : '"';
        $t .= ' style=' . $quot . $style . $quot;
      }
      else if ($key == 'background' || ($key == 'src' && strtolower($node->tagName) == 'img')) { //check tagName anyway
        if (($src = $this->config['cid_map'][$value])
            || ($src = $this->config['cid_map'][$this->config['base_url'].$value])) {
          $t .= ' ' . $key . '="' . htmlspecialchars($src, ENT_QUOTES) . '"';
        }
        else if (preg_match('/^(http|https|ftp):.+/i', $value)) {
          if ($this->config['allow_remote'])
            $t .= ' ' . $key . '="' . htmlspecialchars($value, ENT_QUOTES) . '"';
          else {
            $this->extlinks = true;
            if ($this->config['blocked_src'])
              $t .= ' ' . $key . '="' . htmlspecialchars($this->config['blocked_src'], ENT_QUOTES) . '"';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,7 +214,7 @@
       $key = strtolower($key);
       $value = $node->getAttribute($key);
       if (isset($this->_html_attribs[$key]) ||
-         ($key == 'href' && !preg_match('!^javascript!i', $value)
+         ($key == 'href' && !preg_match('!^(javascript|vbscript|data:text)!i', $value)
            && preg_match('!^([a-z][a-z0-9.+-]+:|//|#).+!i', $value))
       ) {
         $t .= ' ' . $key . '="' . htmlspecialchars($value, ENT_QUOTES) . '"';
```
