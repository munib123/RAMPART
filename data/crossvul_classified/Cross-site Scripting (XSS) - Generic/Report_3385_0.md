# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3385_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3385_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 35-75 of the vulnerable file.

# Get the user object
my (%user, $old);
if ($in{'old'}) {
	%user = ( );
	$in{'name'} = $in{'old'} if (!$access{'rename'});
	&can_edit_user($in{'old'}) || &error($text{'save_euser'});
	$old = &get_user($in{'old'});
	$old || &error($text{'edit_egone'});
	$user{'proto'} = $old->{'proto'};
	$user{'id'} = $old->{'id'};
	$user{'twofactor_provider'} = $old->{'twofactor_provider'};
	$user{'twofactor_id'} = $old->{'twofactor_id'};
	}
else {
	$access{'create'} || &error($text{'save_ecreate'});
	}
&error_setup($text{'save_err'});

# Validate username, and check for a clash
$in{'name'} =~ /^[A-z0-9\-\_\.\@]+$/ && $in{'name'} !~ /^\@/ ||
	&error(&text('save_ename', $in{'name'}));
$in{'name'} eq 'webmin' && &error($text{'save_enamewebmin'});
if (!$in{'old'} || $in{'old'} ne $in{'name'}) {
	my $clash = &get_user($in{'name'});
	$clash && &error(&text('save_edup', $in{'name'}));
	}
!$access{'logouttime'} || $in{'logouttime_def'} ||
	$in{'logouttime'} =~ /^\d+$/ || &error($text{'save_elogouttime'});
!$access{'minsize'} || $in{'minsize_def'} ||
	$in{'minsize'} =~ /^\d+$/ || &error($text{'save_eminsize'});

# Validate password
if ($in{'pass_def'} == 0) {
	$in{'pass'} =~ /:/ && &error($text{'save_ecolon'});
	if (!$in{'temp'}) {
		# Check password quality, unless this is a temp password
		my $perr = &check_password_restrictions($in{'name'},
							$in{'pass'});
		$perr && &error(&text('save_epass', $perr));
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,11 +52,11 @@
 
 # Validate username, and check for a clash
 $in{'name'} =~ /^[A-z0-9\-\_\.\@]+$/ && $in{'name'} !~ /^\@/ ||
-	&error(&text('save_ename', $in{'name'}));
+	&error(&text('save_ename', &html_escape($in{'name'})));
 $in{'name'} eq 'webmin' && &error($text{'save_enamewebmin'});
 if (!$in{'old'} || $in{'old'} ne $in{'name'}) {
 	my $clash = &get_user($in{'name'});
-	$clash && &error(&text('save_edup', $in{'name'}));
+	$clash && &error(&text('save_edup', &html_escape($in{'name'})));
 	}
 !$access{'logouttime'} || $in{'logouttime_def'} ||
 	$in{'logouttime'} =~ /^\d+$/ || &error($text{'save_elogouttime'});
```
