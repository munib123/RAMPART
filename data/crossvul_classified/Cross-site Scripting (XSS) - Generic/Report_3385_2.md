# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3385_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3385_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 17-57 of the vulnerable file.

	$s = $in{'search'};
	for($i=0; $i<$n; $i++) {
		if ($packages{$i,'name'} =~ /\Q$s\E/i ||
		    $packages{$i,'desc'} =~ /\Q$s\E/i) {
			push(@match, $i);
			}
		}
	}
if (@match == 1 && $in{'goto'}) {
	$p = $packages{$match[0],'name'};
	$v = $packages{$match[0],'version'};
	&redirect("edit_pack.cgi?package=".&urlize($p)."&version=".&urlize($v));
	exit;
	}

&ui_print_header(undef, $text{'search_title'}, "", "search");

if (@match) {
	@match = sort { lc($packages{$a,'name'}) cmp lc($packages{$b,'name'}) }
		      @match;
	print "<b>",&text('search_match', "<tt>$s</tt>"),"</b><p>\n";
	print &ui_form_start("delete_packs.cgi", "post");
	print &ui_hidden("search", $in{'search'});
	@tds = ( "width=5" );
	@links = ( &select_all_link("del", 0),
		   &select_invert_link("del", 0) );
	print &ui_links_row(\@links);
	print &ui_columns_start([ "",
				  $text{'search_pack'},
				  $text{'search_class'},
				  $text{'search_desc'} ], 100, 0, \@tds);
	foreach $i (@match) {
		local @cols;
		local $v = $packages{$i,'shortversion'} ||
			   $packages{$i,'version'};
		push(@cols, &ui_link("edit_pack.cgi?search=$s&package=".
		      &urlize($packages{$i,'name'})."&version=".
		      &urlize($packages{$i,'version'}), &html_escape(
			$packages{$i,'name'}.($v ?  " $v" : "")) ) );
		$c = $packages{$i,'class'};
		push(@cols, $c ? &html_escape($c)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,8 @@
 if (@match) {
 	@match = sort { lc($packages{$a,'name'}) cmp lc($packages{$b,'name'}) }
 		      @match;
-	print "<b>",&text('search_match', "<tt>$s</tt>"),"</b><p>\n";
+	print "<b>",&text('search_match',
+			  "<tt>".&html_escape($s)."</tt>"),"</b><p>\n";
 	print &ui_form_start("delete_packs.cgi", "post");
 	print &ui_hidden("search", $in{'search'});
 	@tds = ( "width=5" );
```
