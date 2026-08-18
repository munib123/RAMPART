# CrossVul Fix Pair: Improper Input Validation in perl
**Pair ID:** 3676_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3676_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```perl
Lines 1-29 of the vulnerable file.

#!/usr/local/bin/perl
# save_mon.cgi
# Create, update or delete a monitor

require './status-lib.pl';
$access{'edit'} || &error($text{'mon_ecannot'});
&ReadParse();
if ($in{'type'}) {
	$serv->{'type'} = $in{'type'};
	$serv->{'id'} = time();
	}
else {
	$serv = &get_service($in{'id'});
	$serv->{'oldremote'} = $serv->{'remote'};
	}

if ($in{'delete'}) {
	# Delete the monitor
	&delete_service($serv);
	&webmin_log("delete", undef, $serv->{'id'}, $serv);
	}
elsif ($in{'newclone'}) {
	# Redirect to creation form, in clone mode
	&redirect("edit_mon.cgi?type=$serv->{'type'}&clone=$in{'id'}");
	exit(0);
	}
else {
	# Parse and validate inputs
	&error_setup($text{'mon_err'});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 $access{'edit'} || &error($text{'mon_ecannot'});
 &ReadParse();
 if ($in{'type'}) {
+	$in{'type'} =~ /^[a-zA-Z0-9\_\-\.]+$/ || &error($text{'mon_etype'});
 	$serv->{'type'} = $in{'type'};
 	$serv->{'id'} = time();
 	}
```
