# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5588_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5588_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 347-387 of the vulnerable file.

#------------------------------------------------------------------------------
# If arg is a valid number, return it.  Otherwise, return null.
function clean_number( $value )
{
  return is_numeric( $value ) ? $value : null;
}

#------------------------------------------------------------------------------
# Return true if string is a 3 or 6 character hex color.Return false otherwise.
function is_valid_hex_color( $string )
{
  $return_value = false;
  if( strlen( $string ) == 6 || strlen( $string ) == 3 ) {
    if( preg_match( '/^[0-9a-fA-F]+$/', $string ) ) {
      $return_value = true;
    }
  }
  return $return_value;
    
}

#------------------------------------------------------------------------------
# Return a shortened version of a FQDN
# if "hostname" is numeric only, assume it is an IP instead
# 
function strip_domainname( $hostname ) {
    $postition = strpos($hostname, '.');
    $name = substr( $hostname , 0, $postition );
    if ( FALSE === $postition || is_numeric($name) ) {
        return $hostname;
    } else {
        return $name;
    }
}

#------------------------------------------------------------------------------
# Read a file containing key value pairs
function file_to_hash($filename, $sep)
{
  
  $lines = file($filename, FILE_IGNORE_NEW_LINES);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -364,6 +364,18 @@
   return $return_value;
     
 }
+
+#------------------------------------------------------------------------------
+# Allowed view name characters are alphanumeric plus space, dash and underscore
+function is_proper_view_name( $string )
+{
+  if(preg_match("/[^a-zA-z0-9_\-\ ]/", $string)){
+    return false;
+  } else {
+    return true;
+  }
+}
+
 
 #------------------------------------------------------------------------------
 # Return a shortened version of a FQDN
```
