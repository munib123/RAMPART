# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 2959_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2959_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 23-64 of the vulnerable file.

else {
	@user_info = ( "root", undef, 0, 0 );
	}

# substitute parameters into command
($env, $export, $str, $displaystr) = &set_parameter_envs(
					$cmd, $cmd->{'cmd'}, \@user_info);

# work out hosts
@hosts = @{$cmd->{'hosts'}};
@hosts = ( 0 ) if (!@hosts);
@servers = &list_servers();

# Run and display output
if ($cmd->{'format'} ne 'redirect' && $cmd->{'format'} ne 'form') {
	if ($cmd->{'format'}) {
		print "Content-type: ",$cmd->{'format'},"\n";
		print "\n";
		}
	else {
		&ui_print_unbuffered_header($cmd->{'desc'}, $text{'run_title'},
					    "", -d "help" ? "run" : undef);
		}
	}

&remote_error_setup(\&remote_custom_handler);

foreach $h (@hosts) {
	($server) = grep { $_->{'id'} eq $h } @servers;
	next if (!$server);
	$txt = $cmd->{'noshow'} ? 'run_out2' : 'run_out';
	if (@{$cmd->{'hosts'}}) {
		$txt .= 'on';
		}
	if (!$cmd->{'format'}) {
		print &text($txt, "<tt>".&html_escape($displaystr)."</tt>",
		    $server->{'desc'} || "<tt>$server->{'host'}</tt>"),"\n";
		print "<pre>" if (!$cmd->{'raw'});
		}
	$remote_custom_error = undef;
	if ($h == 0) {
		# Run locally
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,8 +40,9 @@
 		print "\n";
 		}
 	else {
-		&ui_print_unbuffered_header($cmd->{'desc'}, $text{'run_title'},
-					    "", -d "help" ? "run" : undef);
+		&ui_print_unbuffered_header(
+			&html_escape($cmd->{'desc'}), $text{'run_title'},
+			"", -d "help" ? "run" : undef);
 		}
 	}
 
```
