# CrossVul Fix Pair: Improper Input Validation in perl
**Pair ID:** 3676_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3676_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```perl
Lines 1-32 of the vulnerable file.

#!/usr/local/bin/perl
# edit_mon.cgi
# Display a form for editing or creating a monitor

require './status-lib.pl';
$access{'edit'} || &error($text{'mon_ecannot'});
&foreign_require("servers", "servers-lib.pl");
&ReadParse();
@handlers = &list_handlers();
if ($in{'type'}) {
	# Create a new monitor
	$type = $in{'type'};
	$title = $text{'mon_create'};
	if ($in{'clone'}) {
		# Clone of existing
		$serv = &get_service($in{'clone'});
		}
	else {
		# Totally new
		$serv = { 'notify' => 'email pager snmp sms',
			  'fails' => 1,
			  'nosched' => 0,
			  'remote' => '*' };
		}
	}
else {
	# Editing an existing monitor
	$serv = &get_service($in{'id'});
	$type = $serv->{'type'};
	$title = $text{'mon_edit'};
	}
($han) = grep { $_->[0] eq $type } @handlers;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 @handlers = &list_handlers();
 if ($in{'type'}) {
 	# Create a new monitor
+	$in{'type'} =~ /^[a-zA-Z0-9\_\-\.]+$/ || &error($text{'mon_etype'});
 	$type = $in{'type'};
 	$title = $text{'mon_create'};
 	if ($in{'clone'}) {
```
