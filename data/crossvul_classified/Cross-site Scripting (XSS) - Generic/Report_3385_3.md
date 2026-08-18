# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3385_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3385_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 1-22 of the vulnerable file.

#!/usr/local/bin/perl
# change_referers.cgi
# Change referer checking settings

require './webmin-lib.pl';
&ReadParse();
&error_setup($text{'referers_err'});

&lock_file("$config_directory/config");
$gconfig{'referer'} = $in{'referer'};
@refs = split(/\s+/, $in{'referers'});
foreach my $r (@refs) {
	$r =~ /^[a-z0-9\.\-\_]+$/ || &error(&text('referers_ehost', $r));
	}
$gconfig{'referers'} = join(" ", @refs);
$gconfig{'referers_none'} = int(!$in{'referers_none'});
&write_file("$config_directory/config", \%gconfig);
&unlock_file("$config_directory/config");
&webmin_log('referers', undef, undef, \%in);

&redirect("");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,8 @@
 $gconfig{'referer'} = $in{'referer'};
 @refs = split(/\s+/, $in{'referers'});
 foreach my $r (@refs) {
-	$r =~ /^[a-z0-9\.\-\_]+$/ || &error(&text('referers_ehost', $r));
+	$r =~ /^[a-z0-9\.\-\_]+$/ ||
+		&error(&text('referers_ehost', &html_escape($r)));
 	}
 $gconfig{'referers'} = join(" ", @refs);
 $gconfig{'referers_none'} = int(!$in{'referers_none'});
```
