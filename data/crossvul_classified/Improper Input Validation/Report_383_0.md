# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 383_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `383_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 1054-1100 of the vulnerable file.

		case a.Rp, a.Rt:
			if p.elementInScope(defaultScope, a.Ruby) {
				p.generateImpliedEndTags("rtc")
			}
			p.addElement()
		case a.Math, a.Svg:
			p.reconstructActiveFormattingElements()
			if p.tok.DataAtom == a.Math {
				adjustAttributeNames(p.tok.Attr, mathMLAttributeAdjustments)
			} else {
				adjustAttributeNames(p.tok.Attr, svgAttributeAdjustments)
			}
			adjustForeignAttributes(p.tok.Attr)
			p.addElement()
			p.top().Namespace = p.tok.Data
			if p.hasSelfClosingToken {
				p.oe.pop()
				p.acknowledgeSelfClosingTag()
			}
			return true
		case a.Frame:
			// TODO: remove this divergence from the HTML5 spec.
			if p.oe.contains(a.Template) {
				p.addElement()
				return true
			}
		case a.Caption, a.Col, a.Colgroup, a.Head, a.Tbody, a.Td, a.Tfoot, a.Th, a.Thead, a.Tr:
			// Ignore the token.
		default:
			p.reconstructActiveFormattingElements()
			p.addElement()
		}
	case EndTagToken:
		switch p.tok.DataAtom {
		case a.Body:
			if p.elementInScope(defaultScope, a.Body) {
				p.im = afterBodyIM
			}
		case a.Html:
			if p.elementInScope(defaultScope, a.Body) {
				p.parseImpliedToken(EndTagToken, a.Body, a.Body.String())
				return false
			}
			return true
		case a.Address, a.Article, a.Aside, a.Blockquote, a.Button, a.Center, a.Details, a.Dir, a.Div, a.Dl, a.Fieldset, a.Figcaption, a.Figure, a.Footer, a.Header, a.Hgroup, a.Listing, a.Menu, a.Nav, a.Ol, a.Pre, a.Section, a.Summary, a.Ul:
			p.popUntil(defaultScope, p.tok.DataAtom)
		case a.Form:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1071,13 +1071,7 @@
 				p.acknowledgeSelfClosingTag()
 			}
 			return true
-		case a.Frame:
-			// TODO: remove this divergence from the HTML5 spec.
-			if p.oe.contains(a.Template) {
-				p.addElement()
-				return true
-			}
-		case a.Caption, a.Col, a.Colgroup, a.Head, a.Tbody, a.Td, a.Tfoot, a.Th, a.Thead, a.Tr:
+		case a.Caption, a.Col, a.Colgroup, a.Frame, a.Head, a.Tbody, a.Td, a.Tfoot, a.Th, a.Thead, a.Tr:
 			// Ignore the token.
 		default:
 			p.reconstructActiveFormattingElements()
@@ -1925,11 +1919,6 @@
 			p.acknowledgeSelfClosingTag()
 		case a.Noframes:
 			return inHeadIM(p)
-		case a.Template:
-			// TODO: remove this divergence from the HTML5 spec.
-			//
-			// See https://bugs.chromium.org/p/chromium/issues/detail?id=829668
-			return inTemplateIM(p)
 		}
 	case EndTagToken:
 		switch p.tok.DataAtom {
```
