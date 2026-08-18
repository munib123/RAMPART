# CrossVul Fix Pair: Resource Management Errors in ruby
**Pair ID:** 2382_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2382_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```ruby
Lines 261-301 of the vulnerable file.

    when Spc, ?\t, ?\n, ?\r then [:space, s[0,1], s[0,1]]
    else
      numtok(s)
    end
  end


  def nulltok(s);  s[0,4] == 'null'  ? [:val, 'null',  nil]   : [] end
  def truetok(s);  s[0,4] == 'true'  ? [:val, 'true',  true]  : [] end
  def falsetok(s); s[0,5] == 'false' ? [:val, 'false', false] : [] end


  def numtok(s)
    m = /-?([1-9][0-9]+|[0-9])([.][0-9]+)?([eE][+-]?[0-9]+)?/.match(s)
    if m && m.begin(0) == 0
      if !m[2] && !m[3]
        [:val, m[0], Integer(m[0])]
      elsif m[2]
        [:val, m[0], Float(m[0])]
      else
        [:val, m[0], Integer(m[1])*(10**m[3][1..-1].to_i(10))]
      end
    else
      []
    end
  end


  def strtok(s)
    m = /"([^"\\]|\\["\/\\bfnrt]|\\u[0-9a-fA-F]{4})*"/.match(s)
    if ! m
      raise Error, "invalid string literal at #{abbrev(s)}"
    end
    [:str, m[0], unquote(m[0])]
  end


  def abbrev(s)
    t = s[0,10]
    p = t['`']
    t = t[0,p] if p
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -278,7 +278,8 @@
       elsif m[2]
         [:val, m[0], Float(m[0])]
       else
-        [:val, m[0], Integer(m[1])*(10**m[3][1..-1].to_i(10))]
+        # We don't convert scientific notation
+        [:val, m[0], m[0]]
       end
     else
       []
```
