# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3774_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3774_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 512-552 of the vulnerable file.

      if (in_array($attr, $allow_attrib))
        $field_attrib[$attr] = $value;

    // create teaxtarea object
    $input = new $field_type($field_attrib);
    $out = $input->show($MESSAGE->compose[$param]);
  }

  if ($form_start)
    $out = $form_start.$out;

  // configure autocompletion
  rcube_autocomplete_init();

  return $out;
}


function rcmail_compose_header_from($attrib)
{
  global $MESSAGE, $OUTPUT;

  // pass the following attributes to the form class
  $field_attrib = array('name' => '_from');
  foreach ($attrib as $attr => $value)
    if (in_array($attr, array('id', 'class', 'style', 'size', 'tabindex')))
      $field_attrib[$attr] = $value;

  if (count($MESSAGE->identities))
  {
    $a_signatures = array();

    $field_attrib['onchange'] = JS_OBJECT_NAME.".change_identity(this)";
    $select_from = new html_select($field_attrib);

    // create SELECT element
    foreach ($MESSAGE->identities as $sql_arr)
    {
      $identity_id = $sql_arr['identity_id'];
      $select_from->add(format_email_recipient($sql_arr['email'], $sql_arr['name']), $identity_id);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -529,7 +529,7 @@
 
 function rcmail_compose_header_from($attrib)
 {
-  global $MESSAGE, $OUTPUT;
+  global $MESSAGE, $OUTPUT, $RCMAIL, $compose_mode;
 
   // pass the following attributes to the form class
   $field_attrib = array('name' => '_from');
@@ -540,6 +540,8 @@
   if (count($MESSAGE->identities))
   {
     $a_signatures = array();
+    $separator    = $RCMAIL->config->get('sig_above')
+      && ($compose_mode == RCUBE_COMPOSE_REPLY || $compose_mode == RCUBE_COMPOSE_FORWARD) ? '---' : '-- ';
 
     $field_attrib['onchange'] = JS_OBJECT_NAME.".change_identity(this)";
     $select_from = new html_select($field_attrib);
@@ -553,13 +555,27 @@
       // add signature to array
       if (!empty($sql_arr['signature']) && empty($COMPOSE['param']['nosig']))
       {
-        $a_signatures[$identity_id]['text'] = $sql_arr['signature'];
-        $a_signatures[$identity_id]['is_html'] = ($sql_arr['html_signature'] == 1) ? true : false;
-        if ($a_signatures[$identity_id]['is_html'])
-        {
-            $h2t = new html2text($a_signatures[$identity_id]['text'], false, false);
-            $a_signatures[$identity_id]['plain_text'] = trim($h2t->get_text());
+        $text = $html = $sql_arr['signature'];
+
+        if ($sql_arr['html_signature']) {
+            $h2t  = new html2text($sql_arr['signature'], false, false);
+            $text = trim($h2t->get_text());
         }
+        else {
+            $html = htmlentities($html, ENT_NOQUOTES, RCMAIL_CHARSET);
+        }
+
+        if (!preg_match('/^--[ -]\r?\n/m', $text)) {
+            $text = $separator . "\n" . $text;
+            $html = $separator . "<br>" . $html;
+        }
+
+        if (!$sql_arr['html_signature']) {
+            $html = "<pre>" . $html . "</pre>";
+        }
+
+        $a_signatures[$identity_id]['text'] = $text;
+        $a_signatures[$identity_id]['html'] = $html;
       }
     }
 
```
