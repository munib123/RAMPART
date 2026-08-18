# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3384_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3384_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 26-67 of the vulnerable file.

	push(@sects, $1);
	}
SECT: foreach $sec (@sects) {
	foreach $page ($in{'page'}, lc($in{'page'})) {
		$page =~ /\// && &error($text{'man_epath'});
		$qpage = quotemeta($page);
		$qsec = quotemeta($sec);
		$cmd = $ocmd;
		$cmd =~ s/PAGE/$qpage/;
		$cmd =~ s/SECTION/$qsec/;
		$out = &backquote_command("$cmd 2>&1", 1);
		if ($out !~ /^.*no manual entry/i && $out !~ /^.*no entry/i &&
		    $out !~ /^.*nothing appropriate/i) {
			# Found it
			$found++;
			last SECT;
			}
		}
	}
if (!$found) {
	print "<p><b>",&text('man_noentry', "<tt>$in{'page'}</tt>"),
	      "</b><p>\n";
	}
else {
	if (&has_command($config{'man2html_path'})) {
		# Last line only
		@lines = split(/\r?\n/, $out);
		$out = $lines[$#lines];
                if ($out =~ /\(<--\s+(.*)\)/) {
                        # Output has cached file and original path
                        $out = $1;
                        }
		$out =~ s/ .*//;
		if( $out =~ /^.*\.gz/i ) {
			$cmd = "gunzip -c";
			}
		elsif ($out =~ /^.*\.(bz2|bz)/i) {
			$cmd = "bunzip2 -c";
			}
		else {
			$cmd = "cat";
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,8 +43,8 @@
 		}
 	}
 if (!$found) {
-	print "<p><b>",&text('man_noentry', "<tt>$in{'page'}</tt>"),
-	      "</b><p>\n";
+	print "<p><b>",&text('man_noentry',
+		     "<tt>".&html_escape($in{'page'})."</tt>"),"</b><p>\n";
 	}
 else {
 	if (&has_command($config{'man2html_path'})) {
@@ -86,13 +86,19 @@
 			$out =~ s/<A HREF="file:[^"]+">([^<]+)<\/a>/$1/ig;
 			$out =~ s/<A HREF="view_man.cgi">/<A HREF=\"\">/i;
 			}
-		&show_view_table(&text('man_header', $in{'page'}, $in{'sec'}),
-				 $out);
+		&show_view_table(
+			&text('man_header',
+			      &html_escape($in{'page'}),
+			      &html_escape($in{'sec'})),
+			$out);
 	} else {
 		$out =~ s/.\010//g;
 		$out =~ s/^(man:\s*)?(re)?formatting.*//i;
-		&show_view_table(&text('man_header', $in{'page'}, $in{'sec'}),
-				 "<pre>".&html_escape($out)."</pre>");
+		&show_view_table(
+			&text('man_header',
+			      &html_escape($in{'page'}),
+			      &html_escape($in{'sec'})),
+			"<pre>".&html_escape($out)."</pre>");
 		}
 	}
 
```
