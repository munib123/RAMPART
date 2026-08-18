# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5189_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5189_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 258-300 of the vulnerable file.

      if (array_key_exists($string, $this->cache_translations))
        return $this->cache_translations[$string];
      else
        return $string;
    } else {
      // Caching not enabled, try to find string
      $num = $this->find_string($string);
      if ($num == -1)
        return $string;
      else
        return $this->get_translation_string($num);
    }
  }

  /**
   * Sanitize plural form expression for use in PHP eval call.
   *
   * @access private
   * @return string sanitized plural form expression
   */
  function sanitize_plural_expression($expr) {
    // Get rid of disallowed characters.
    $expr = preg_replace('@[^a-zA-Z0-9_:;\(\)\?\|\&=!<>+*/\%-]@', '', $expr);

    // Add parenthesis for tertiary '?' operator.
    $expr .= ';';
    $res = '';
    $p = 0;
    for ($i = 0; $i < strlen($expr); $i++) {
      $ch = $expr[$i];
      switch ($ch) {
      case '?':
        $res .= ' ? (';
        $p++;
        break;
      case ':':
        $res .= ') : (';
        break;
      case ';':
        $res .= str_repeat( ')', $p) . ';';
        $p = 0;
        break;
      default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -275,34 +275,34 @@
    * @access private
    * @return string sanitized plural form expression
    */
-  function sanitize_plural_expression($expr) {
-    // Get rid of disallowed characters.
-    $expr = preg_replace('@[^a-zA-Z0-9_:;\(\)\?\|\&=!<>+*/\%-]@', '', $expr);
-
-    // Add parenthesis for tertiary '?' operator.
-    $expr .= ';';
-    $res = '';
-    $p = 0;
-    for ($i = 0; $i < strlen($expr); $i++) {
-      $ch = $expr[$i];
-      switch ($ch) {
-      case '?':
-        $res .= ' ? (';
-        $p++;
-        break;
-      case ':':
-        $res .= ') : (';
-        break;
-      case ';':
-        $res .= str_repeat( ')', $p) . ';';
-        $p = 0;
-        break;
-      default:
-        $res .= $ch;
-      }
-    }
-    return $res;
-  }
+  //function sanitize_plural_expression($expr) {
+  //  // Get rid of disallowed characters.
+  //  $expr = preg_replace('@[^a-zA-Z0-9_:;\(\)\?\|\&=!<>+*/\%-]@', '', $expr);
+
+  //  // Add parenthesis for tertiary '?' operator.
+  //  $expr .= ';';
+  //  $res = '';
+  //  $p = 0;
+  //  for ($i = 0; $i < strlen($expr); $i++) {
+  //    $ch = $expr[$i];
+  //    switch ($ch) {
+  //    case '?':
+  //      $res .= ' ? (';
+  //      $p++;
+  //      break;
+  //    case ':':
+  //      $res .= ') : (';
+  //      break;
+  //    case ';':
+  //      $res .= str_repeat( ')', $p) . ';';
+  //      $p = 0;
+  //      break;
+  //    default:
+  //      $res .= $ch;
+  //    }
+  //  }
+  //  return $res;
+  //}
 
   /**
    * Parse full PO header and extract only plural forms line.
@@ -310,13 +310,13 @@
    * @access private
    * @return string verbatim plural form header field
    */
-  function extract_plural_forms_header_from_po_header($header) {
-    if (preg_match("/(^|\n)plural-forms: ([^\n]*)\n/i", $header, $regs))
-      $expr = $regs[2];
-    else
-      $expr = "nplurals=2; plural=n == 1 ? 0 : 1;";
-    return $expr;
-  }
+  //function extract_plural_forms_header_from_po_header($header) {
+  //  if (preg_match("/(^|\n)plural-forms: ([^\n]*)\n/i", $header, $regs))
+  //    $expr = $regs[2];
+  //  else
+  //    $expr = "nplurals=2; plural=n == 1 ? 0 : 1;";
+  //  return $expr;
+  //}
 
   /**
    * Get possible plural forms from MO header
@@ -324,23 +324,24 @@
    * @access private
    * @return string plural form header
    */
-  function get_plural_forms() {
-    // lets assume message number 0 is header
-    // this is true, right?
-    $this->load_tables();
-
-    // cache header field for plural forms
-    if (! is_string($this->pluralheader)) {
-      if ($this->enable_cache) {
-        $header = $this->cache_translations[""];
-      } else {
-        $header = $this->get_translation_string(0);
-      }
-      $expr = $this->extract_plural_forms_header_from_po_header($header);
-      $this->pluralheader = $this->sanitize_plural_expression($expr);
-    }
-    return $this->pluralheader;
-  }
+  //function get_plural_forms() {
+  //  // lets assume message number 0 is header
+  //  // this is true, right?
+  //  $this->load_tables();
+
+  //  // cache header field for plural forms
+  //  if (! is_string($this->pluralheader)) {
+  //    if ($this->enable_cache) {
+  //      $header = $this->cache_translations[""];
+  //    } else {
+  //      $header = $this->get_translation_string(0);
+  //    }
+  //    print($header);
+  //    $expr = $this->extract_plural_forms_header_from_po_header($header);
+  //    $this->pluralheader = $this->sanitize_plural_expression($expr);
+  //  }
+  //  return $this->pluralheader;
+  //}
 
   /**
    * Detects which plural form to take
@@ -349,23 +350,23 @@
    * @param n count
    * @return int array index of the right plural form
    */
-  function select_string($n) {
-    if (!is_int($n)) {
-      throw new InvalidArgumentException(
-        "Select_string only accepts integers: " . $n);
-    }
-    $string = $this->get_plural_forms();
-    $string = str_replace('nplurals',"\$total",$string);
-    $string = str_replace("n",$n,$string);
-    $string = str_replace('plural',"\$plural",$string);
-
-    $total = 0;
-    $plural = 0;
-
-    eval("$string");
-    if ($plural >= $total) $plural = $total - 1;
-    return $plural;
-  }
+  //function select_string($n) {
+  //  if (!is_int($n)) {
+  //    throw new InvalidArgumentException(
+  //      "Select_string only accepts integers: " . $n);
+  //  }
+  //  $string = $this->get_plural_forms();
+  //  $string = str_replace('nplurals',"\$total",$string);
+  //  $string = str_replace("n",$n,$string);
+  //  $string = str_replace('plural',"\$plural",$string);
+
+  //  $total = 0;
+  //  $plural = 0;
+
+  //  eval("$string");
+  //  if ($plural >= $total) $plural = $total - 1;
+  //  return $plural;
+  //}
 
   /**
    * Plural version of gettext
@@ -376,40 +377,40 @@
    * @param string number
    * @return translated plural form
    */
-  function ngettext($single, $plural, $number) {
-    if ($this->short_circuit) {
-      if ($number != 1)
-        return $plural;
-      else
-        return $single;
-    }
-
-    // find out the appropriate form
-    $select = $this->select_string($number);
-
-    // this should contains all strings separated by NULLs
-    $key = $single . chr(0) . $plural;
-
-
-    if ($this->enable_cache) {
-      if (! array_key_exists($key, $this->cache_translations)) {
-        return ($number != 1) ? $plural : $single;
-      } else {
-        $result = $this->cache_translations[$key];
-        $list = explode(chr(0), $result);
-        return $list[$select];
-      }
-    } else {
-      $num = $this->find_string($key);
-      if ($num == -1) {
-        return ($number != 1) ? $plural : $single;
-      } else {
-        $result = $this->get_translation_string($num);
-        $list = explode(chr(0), $result);
-        return $list[$select];
-      }
-    }
-  }
+  //function ngettext($single, $plural, $number) {
+  //  if ($this->short_circuit) {
+  //    if ($number != 1)
+  //      return $plural;
+  //    else
+  //      return $single;
+  //  }
+
+  //  // find out the appropriate form
+  //  $select = $this->select_string($number);
+
+  //  // this should contains all strings separated by NULLs
+  //  $key = $single . chr(0) . $plural;
+
+
+  //  if ($this->enable_cache) {
+  //    if (! array_key_exists($key, $this->cache_translations)) {
+  //      return ($number != 1) ? $plural : $single;
+  //    } else {
+  //      $result = $this->cache_translations[$key];
+  //      $list = explode(chr(0), $result);
+  //      return $list[$select];
+  //    }
+  //  } else {
+  //    $num = $this->find_string($key);
+  //    if ($num == -1) {
+  //      return ($number != 1) ? $plural : $single;
+  //    } else {
+  //      $result = $this->get_translation_string($num);
+  //      $list = explode(chr(0), $result);
+  //      return $list[$select];
+  //    }
+  //  }
+  //}
 
   function pgettext($context, $msgid) {
     $key = $context . chr(4) . $msgid;
@@ -421,16 +422,16 @@
     }
   }
 
-  function npgettext($context, $singular, $plural, $number) {
-    $key = $context . chr(4) . $singular;
-    $ret = $this->ngettext($key, $plural, $number);
-    if (strpos($ret, "\004") !== FALSE) {
-      return $singular;
-    } else {
-      return $ret;
-    }
-
-  }
+  //function npgettext($context, $singular, $plural, $number) {
+  //  $key = $context . chr(4) . $singular;
+  //  $ret = $this->ngettext($key, $plural, $number);
+  //  if (strpos($ret, "\004") !== FALSE) {
+  //    return $singular;
+  //  } else {
+  //    return $ret;
+  //  }
+
+  //}
 }
 
 ?>
```
