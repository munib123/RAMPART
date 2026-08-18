# CrossVul Fix Pair: Improper Validation of Array Index in go
**Pair ID:** 2004_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2004_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```go
Lines 827-867 of the vulnerable file.

			p.decodeVarint("wire", "uint64")
			p.P(`fieldNum := int32(wire >> 3)`)

			p.P(`if fieldNum == 1 {`)
			p.In()
			p.mapField("mapkey", false, m.KeyAliasField)
			p.Out()
			p.P(`} else if fieldNum == 2 {`)
			p.In()
			p.mapField("mapvalue", gogoproto.IsCustomType(field), m.ValueAliasField)
			p.Out()
			p.P(`} else {`)
			p.In()
			p.P(`iNdEx = entryPreIndex`)
			p.P(`skippy, err := skip`, p.localName, `(dAtA[iNdEx:])`)
			p.P(`if err != nil {`)
			p.In()
			p.P(`return err`)
			p.Out()
			p.P(`}`)
			p.P(`if skippy < 0 {`)
			p.In()
			p.P(`return ErrInvalidLength`, p.localName)
			p.Out()
			p.P(`}`)
			p.P(`if (iNdEx + skippy) > postIndex {`)
			p.In()
			p.P(`return `, p.ioPkg.Use(), `.ErrUnexpectedEOF`)
			p.Out()
			p.P(`}`)
			p.P(`iNdEx += skippy`)
			p.Out()
			p.P(`}`)

			p.Out()
			p.P(`}`)

			s := `m.` + fieldname
			if keygoTyp == keygoAliasTyp {
				s += `[mapkey]`
			} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -844,7 +844,7 @@
 			p.P(`return err`)
 			p.Out()
 			p.P(`}`)
-			p.P(`if skippy < 0 {`)
+			p.P(`if (skippy < 0) || (iNdEx + skippy) < 0 {`)
 			p.In()
 			p.P(`return ErrInvalidLength`, p.localName)
 			p.Out()
@@ -1484,12 +1484,7 @@
 			p.P(`return err`)
 			p.Out()
 			p.P(`}`)
-			p.P(`if skippy < 0 {`)
-			p.In()
-			p.P(`return ErrInvalidLength`, p.localName)
-			p.Out()
-			p.P(`}`)
-			p.P(`if (iNdEx + skippy) < 0 {`)
+			p.P(`if (skippy < 0) || (iNdEx + skippy) < 0 {`)
 			p.In()
 			p.P(`return ErrInvalidLength`, p.localName)
 			p.Out()
@@ -1512,12 +1507,7 @@
 		p.P(`return err`)
 		p.Out()
 		p.P(`}`)
-		p.P(`if skippy < 0 {`)
-		p.In()
-		p.P(`return ErrInvalidLength`, p.localName)
-		p.Out()
-		p.P(`}`)
-		p.P(`if (iNdEx + skippy) < 0 {`)
+		p.P(`if (skippy < 0) || (iNdEx + skippy) < 0 {`)
 		p.In()
 		p.P(`return ErrInvalidLength`, p.localName)
 		p.Out()
```
