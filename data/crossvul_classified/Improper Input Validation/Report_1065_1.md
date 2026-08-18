# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1065_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1065_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 362-402 of the vulnerable file.

                self.pos += 1
                preserve_ws = False
            elif self.field[self.pos] == '"':
                aslist.append('"%s"' % quote(self.getquote()))
            elif self.field[self.pos] in self.atomends:
                if aslist and not aslist[-1].strip():
                    aslist.pop()
                break
            else:
                aslist.append(self.getatom())
            ws = self.gotonext()
            if preserve_ws and ws:
                aslist.append(ws)

        if self.pos >= len(self.field) or self.field[self.pos] != '@':
            return EMPTYSTRING.join(aslist)

        aslist.append('@')
        self.pos += 1
        self.gotonext()
        return EMPTYSTRING.join(aslist) + self.getdomain()

    def getdomain(self):
        """Get the complete domain name from an address."""
        sdlist = []
        while self.pos < len(self.field):
            if self.field[self.pos] in self.LWS:
                self.pos += 1
            elif self.field[self.pos] == '(':
                self.commentlist.append(self.getcomment())
            elif self.field[self.pos] == '[':
                sdlist.append(self.getdomainliteral())
            elif self.field[self.pos] == '.':
                self.pos += 1
                sdlist.append('.')
            elif self.field[self.pos] in self.atomends:
                break
            else:
                sdlist.append(self.getatom())
        return EMPTYSTRING.join(sdlist)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -379,7 +379,12 @@
         aslist.append('@')
         self.pos += 1
         self.gotonext()
-        return EMPTYSTRING.join(aslist) + self.getdomain()
+        domain = self.getdomain()
+        if not domain:
+            # Invalid domain, return an empty address instead of returning a
+            # local part to denote failed parsing.
+            return EMPTYSTRING
+        return EMPTYSTRING.join(aslist) + domain
 
     def getdomain(self):
         """Get the complete domain name from an address."""
@@ -394,6 +399,10 @@
             elif self.field[self.pos] == '.':
                 self.pos += 1
                 sdlist.append('.')
+            elif self.field[self.pos] == '@':
+                # bpo-34155: Don't parse domains with two `@` like
+                # `a@malicious.org@important.com`.
+                return EMPTYSTRING
             elif self.field[self.pos] in self.atomends:
                 break
             else:
```
