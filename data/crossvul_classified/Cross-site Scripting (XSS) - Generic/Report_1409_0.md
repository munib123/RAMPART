# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1409_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1409_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 433-473 of the vulnerable file.


  global $user;

  if ( $user['Events'] == 'Edit' ) {
    $event->delete();
  } # CAN EDIT
}

function makeLink( $url, $label, $condition=1, $options='' ) {
  $string = '';
  if ( $condition ) {
    $string .= '<a href="'.$url.'"'.($options?(' '.$options):'').'>';
  }
  $string .= $label;
  if ( $condition ) {
    $string .= '</a>';
  }
  return( $string );
}

function makePopupLink( $url, $winName, $winSize, $label, $condition=1, $options='' ) {
  // Avoid double-encoding since some consumers incorrectly pass a pre-escaped URL.
  $string = '<a class="popup-link" href="' . htmlspecialchars($url, ENT_COMPAT | ENT_HTML401, ini_get("default_charset"), false) . '"';
  $string .= ' data-window-name="' . htmlspecialchars($winName) . '"';
  if ( $condition ) {
    if ( is_array( $winSize ) ) {
      $string .= ' data-window-tag="' . htmlspecialchars($winSize[0]) . '"';
      $string .= ' data-window-width="' . htmlspecialchars($winSize[1]) . '"';
      $string .= ' data-window-height="' . htmlspecialchars($winSize[2]) . '"';
    } else {
      $string .= ' data-window-tag="' . htmlspecialchars($winSize) . '"';
    }

    $string .= ($options ? (' ' . $options ) : '') . '>';
  } else {
    $string .= '<a>';
  }
  $string .= $label;
  $string .= '</a>';
  return( $string );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -450,6 +450,9 @@
   return( $string );
 }
 
+/**
+ * $label must be already escaped. It can't be done here since it sometimes contains HTML tags.
+ */
 function makePopupLink( $url, $winName, $winSize, $label, $condition=1, $options='' ) {
   // Avoid double-encoding since some consumers incorrectly pass a pre-escaped URL.
   $string = '<a class="popup-link" href="' . htmlspecialchars($url, ENT_COMPAT | ENT_HTML401, ini_get("default_charset"), false) . '"';
```
