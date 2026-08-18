# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 3489_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3489_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 139-179 of the vulnerable file.

            if strict
              raise "expected <"
            else
              return Text.new(parent, line, pos, content)
            end
          end

          if scanner.skip(/!\[CDATA\[/)
            unless scanner.skip_until(/\]\]>/)
              if strict
                raise "expected ]]> (got #{scanner.rest.inspect} for #{content})"
              else
                scanner.skip_until(/\Z/)
              end
            end

            return CDATA.new(parent, line, pos, scanner.pre_match.gsub(/<!\[CDATA\[/, ''))
          end

          closing = ( scanner.scan(/\//) ? :close : nil )
          return Text.new(parent, line, pos, content) unless name = scanner.scan(/[\w:-]+/)
          name.downcase!

          unless closing
            scanner.skip(/\s*/)
            attributes = {}
            while attr = scanner.scan(/[-\w:]+/)
              value = true
              if scanner.scan(/\s*=\s*/)
                if delim = scanner.scan(/['"]/)
                  value = ""
                  while text = scanner.scan(/[^#{delim}\\]+|./)
                    case text
                      when "\\" then
                        value << text
                        break if scanner.eos?
                        value << scanner.getch
                      when delim
                        break
                      else value << text
                    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,7 +156,7 @@
           end
 
           closing = ( scanner.scan(/\//) ? :close : nil )
-          return Text.new(parent, line, pos, content) unless name = scanner.scan(/[\w:-]+/)
+          return Text.new(parent, line, pos, content) unless name = scanner.scan(/[^\s!>\/]+/)
           name.downcase!
 
           unless closing
```
