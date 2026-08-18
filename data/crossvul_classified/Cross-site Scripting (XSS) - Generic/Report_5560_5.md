# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 512-552 of the vulnerable file.

  $data->assign("additional_filter_options", 'Show only nodes matching <input name=host_regex ' .$set_host_regex_value . '>'
   . '<input class="header_btn" type="SUBMIT" VALUE="Filter">'
   . '&nbsp;<span class="nobr">Max graphs to show <select onChange="ganglia_submit();" name="max_graphs">' . $max_graphs_values . '</select></span>'
    );
} else
  $data->assign("additional_filter_options", '');

if($conf['auth_system'] == 'enabled') {
  $data->assign('auth_system_enabled', true);
  $username = sanitize( GangliaAuth::getInstance()->getUser() );
  $data->assign('username', $username);
} else {
  $data->assign('auth_system_enabled', false);
  $data->assign('username', null);
}


if ( $conf['overlay_events'] == true )
  $data->assign('overlay_events', true);

$data->assign('selected_tab', $user['selected_tab']);
$data->assign('view_name', $user['viewname']);

$additional_buttons = "";
if ($context == 'views' || $context == 'decompose_graph' || $context == 'host') {
  $additional_buttons = '<input title="Hide/Show Events" type="checkbox" id="show_all_events" onclick="showAllEvents(this.checked)"/><label for="show_all_events">Hide/Show Events</label>';
}
$data->assign('additional_buttons', $additional_buttons);

# Make sure that no data is cached..
header ("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); # Date in the past
header ("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT"); # always modified
header ("Cache-Control: no-cache, must-revalidate"); # HTTP/1.1
header ("Pragma: no-cache"); # HTTP/1.0

if (file_exists("./templates/${conf['template_name']}/user_header.tpl"))
  $data->assign('user_header', "1");

$dwoo->output($tpl, $data);

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -529,7 +529,7 @@
 if ( $conf['overlay_events'] == true )
   $data->assign('overlay_events', true);
 
-$data->assign('selected_tab', $user['selected_tab']);
+$data->assign('selected_tab', htmlspecialchars($user['selected_tab']) );
 $data->assign('view_name', $user['viewname']);
 
 $additional_buttons = "";
```
