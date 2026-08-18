# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in perl
**Pair ID:** 3344_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** perl
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3344_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```perl
Lines 56-96 of the vulnerable file.

# Basically don't send a character set for the login page..
         . (ref $cgi && ($cgi->{item} || $cgi->{Nickname}) ? '; charset=utf-8' : ''),
      'Pragma: no-cache',
      'Cache-control: must-revalidate, no-cache',
      'Expires: -1') . "\r\n";

# Please leave this.
my $copy = <<EOF;
<a href="http://cgiirc.org/">CGI:IRC</a> $VERSION<br />
EOF

my $scriptname = $config->{script_login} || 'irc.cgi';

my $interface = ref $cgi && defined $cgi->{interface} ? $cgi->{interface} : 'default';
$interface =~ /^([a-z0-9]+)/;
$interface = $1;
require($interface . '.pm');

if(ref $cgi && defined $cgi->{item}) {
   print "\r\n"; # send final header
   my $name = $cgi->{item};
   exit unless $interface->exists($name);
   $interface->$name($cgi, $config, 0);
}elsif(ref $cgi && defined $cgi->{Nickname}) {
   print "\r\n"; # send final header
   my $r = random();
   my($format, $style);
   
   my %p = ( 
         Nickname => 'nick', 
         Channel => 'chan',
         Port => 'port',
         Server => 'serv',
         Realname => 'name',
         interface => 'interface',
         Password => 'pass',
         Format => 'format',
         'Character_set' => 'charset',
      );
   my $out;
   for(keys %p) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,7 @@
 
 if(ref $cgi && defined $cgi->{item}) {
    print "\r\n"; # send final header
+   error('Communication socket name is invalid') if $cgi->{R} =~ /[^A-Za-z0-9]/;
    my $name = $cgi->{item};
    exit unless $interface->exists($name);
    $interface->$name($cgi, $config, 0);
```
