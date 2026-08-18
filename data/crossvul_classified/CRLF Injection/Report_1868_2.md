# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in ruby
**Pair ID:** 1868_2
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1868_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```ruby
Lines 3-35 of the vulnerable file.

  module Patterns
    white_space = %Q|\x9\x20|
    text        = %Q|\x1-\x8\xB\xC\xE-\x7f|
    field_name  = %Q|\x21-\x39\x3b-\x7e|
    qp_safe     = %Q|\x20-\x3c\x3e-\x7e|
    
    aspecial     = %Q|()<>[]:;@\\,."| # RFC5322
    tspecial     = %Q|()<>@,;:\\"/[]?=| # RFC2045
    sp           = %Q| |
    control      = %Q|\x00-\x1f\x7f-\xff|
    
    if control.respond_to?(:force_encoding)
      control = control.force_encoding(Encoding::BINARY)
    end
    
    CRLF          = /\r\n/
    WSP           = /[#{white_space}]/
    FWS           = /#{CRLF}#{WSP}*/
    TEXT          = /[#{text}]/ # + obs-text
    FIELD_NAME    = /[#{field_name}]+/
    FIELD_BODY    = /.+/
    FIELD_LINE    = /^[#{field_name}]+:\s*.+$/
    FIELD_SPLIT   = /^(#{FIELD_NAME})\s*:\s*(#{FIELD_BODY})?$/
    HEADER_LINE   = /^([#{field_name}]+:\s*.+)$/

    QP_UNSAFE     = /[^#{qp_safe}]/
    QP_SAFE       = /[#{qp_safe}]/
    CONTROL_CHAR  = /[#{control}]/n
    ATOM_UNSAFE   = /[#{Regexp.quote aspecial}#{control}#{sp}]/n
    PHRASE_UNSAFE = /[#{Regexp.quote aspecial}#{control}]/n
    TOKEN_UNSAFE  = /[#{Regexp.quote tspecial}#{control}#{sp}]/n
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,10 +20,12 @@
     FWS           = /#{CRLF}#{WSP}*/
     TEXT          = /[#{text}]/ # + obs-text
     FIELD_NAME    = /[#{field_name}]+/
-    FIELD_BODY    = /.+/
+    FIELD_PREFIX  = /\A(#{FIELD_NAME})/
+    FIELD_BODY    = /.+/m
     FIELD_LINE    = /^[#{field_name}]+:\s*.+$/
     FIELD_SPLIT   = /^(#{FIELD_NAME})\s*:\s*(#{FIELD_BODY})?$/
     HEADER_LINE   = /^([#{field_name}]+:\s*.+)$/
+    HEADER_SPLIT  = /#{CRLF}(?!#{WSP})/
 
     QP_UNSAFE     = /[^#{qp_safe}]/
     QP_SAFE       = /[#{qp_safe}]/
```
