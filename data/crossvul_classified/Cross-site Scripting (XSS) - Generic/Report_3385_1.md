# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3385_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3385_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 3-43 of the vulnerable file.

# Display information about a file owned by the package management system

require './software-lib.pl';
&ReadParse();
$f = $in{'file'};
&ui_print_header(undef, $text{'file_title'}, "", "file_info");

$f =~ s/\/$//;
if ($f !~ /^\//) {
	# if the filename is not absolute, look for it
	foreach $p (split(/:/, $ENV{'PATH'})) {
		last if (&installed_file("$p/$f") && %file);
		}
	}
else {
	# absolute path.. must exist in DB
	&installed_file($f);
	}

if (!%file) {
	print "<b>",&text('file_notfound', "<tt>$f</tt>"),"</b><p>\n";
	}
else {
	# display file info
	$nc = "width=10% nowrap";
	print &ui_table_start($text{'file_title'}, "width=100%", 4);

	print &ui_table_row($text{'file_path'},
			    "<tt>".&html_escape($file{'path'})."</tt>", 3);

	print &ui_table_row($text{'file_type'},
			    $type_map[$file{'type'}]);

	if ($file{'type'} != 3 && $file{'type'} != 4) {
		print &ui_table_row($text{'file_perms'}, $file{'mode'});

		print &ui_table_row($text{'file_owner'}, $file{'user'});
		print &ui_table_row($text{'file_group'}, $file{'group'});

		if ($file{'type'} == 0) {
			print &ui_table_row($text{'file_size'}, $file{'size'});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,8 @@
 	}
 
 if (!%file) {
-	print "<b>",&text('file_notfound', "<tt>$f</tt>"),"</b><p>\n";
+	print "<b>",&text('file_notfound',
+			  "<tt>".&html_escape($f)."</tt>"),"</b><p>\n";
 	}
 else {
 	# display file info
```
