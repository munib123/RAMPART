# CrossVul Fix Pair: Improper Authentication in perl
**Pair ID:** 3678_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3678_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```perl
Lines 1-33 of the vulnerable file.

#!/usr/local/bin/perl
# Show an HTML editor window

$trust_unknown_referers = 1;
require './file-lib.pl';
do '../ui-lib.pl';
$disallowed_buttons{'edit'} && &error($text{'ebutton'});
&ReadParse();

# Work out editing mode
if ($in{'text'} || $in{'file'} && !&is_html_file($in{'file'})) {
	$text_mode = 1;
	}

&popup_header($in{'file'} ? $text{'html_title'} : $text{'html_title2'},
	      undef, $text_mode ? undef : "onload='xinha_init()'");

# Output HTMLarea init code
print <<EOF;
<script type="text/javascript">
  _editor_url = "$gconfig{'webprefix'}/$module_name/xinha/";
  _editor_lang = "en";
</script>
<script type="text/javascript" src="xinha/XinhaCore.js"></script>

<script type="text/javascript">
xinha_init = function()
{
xinha_editors = [ "body" ];
xinha_plugins = [ ];
xinha_config = new Xinha.Config();
xinha_editors = Xinha.makeEditors(xinha_editors, xinha_config, xinha_plugins);
Xinha.startEditors(xinha_editors);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,11 @@
 # Work out editing mode
 if ($in{'text'} || $in{'file'} && !&is_html_file($in{'file'})) {
 	$text_mode = 1;
+	}
+
+if (!&can_access($in{'file'})) {
+	# ACL rules prevent access to file
+	&error_exit(&text('view_eaccess', &html_escape($in{'file'})));
 	}
 
 &popup_header($in{'file'} ? $text{'html_title'} : $text{'html_title2'},
```
